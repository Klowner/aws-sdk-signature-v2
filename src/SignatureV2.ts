import {prepareRequest} from "@aws-sdk/signature-v4";
import type {
  Credentials,
  HashConstructor,
  HeaderBag,
  HttpRequest,
  Provider,
  QueryParameterBag,
  RequestSigner,
  RequestSigningArguments,
} from "@aws-sdk/types";
import { normalizeProvider } from "@aws-sdk/util-middleware";
import { toBase64 } from "@aws-sdk/util-base64-browser";
import { Sha1 } from "@aws-crypto/sha1-browser";

export interface SignatureV2Init {
  service: string;
  credentials: Credentials | Provider<Credentials>;
}

export class SignatureV2 implements RequestSigner {
  private readonly credentialProvider: Provider<Credentials>;
  private readonly toBase64 = toBase64;
  private readonly sha1: HashConstructor;

  constructor({
    credentials,
  }: SignatureV2Init) {
    this.credentialProvider = normalizeProvider(credentials);
    this.sha1 = Sha1;
  }

  async sign(stringToSign: string): Promise<string>;
  async sign(requestToSign: HttpRequest): Promise<HttpRequest>;
  async sign(toSign: string|HttpRequest) {
    const credentials = await this.credentialProvider();
    if (typeof toSign === 'string') {
      return this.signString(credentials.secretAccessKey, toSign);
    }
    return this.signRequest(credentials, toSign);
  }

  async signString(
    secret: string,
    stringToHash: string,
  ): Promise<string> {
    const hash = new this.sha1(secret);
    hash.update(stringToHash);
    const signature = this.toBase64(await hash.digest());
    return signature;
  }

  async signRequest(
    credentials: Credentials,
    requestToSign: HttpRequest,
    {}: RequestSigningArguments = {},
  ): Promise<HttpRequest> {
    const request = prepareRequest(requestToSign);
    const date = (new Date).toUTCString().replace('GMT', '+0000');
    request.headers['x-amz-date'] = date;
    const stringToSign = signableStringForRequest(request);
    const signature = await this.signString(credentials.secretAccessKey, stringToSign);
    request.headers = {
      ...request.headers,
      'Authorization': 'AWS ' + credentials.accessKeyId + ':' + signature,
    };
    return request;
  }
}

export function signableStringForRequest(
  request: HttpRequest
): string {
  const parts = [];
  parts.push(request.method);
  parts.push(request.headers['content-md5'] || '');
  parts.push(request.headers['content-type'] || '');
  parts.push(request.headers['date'] || '');
  const headers = assembleHeaders(request.headers);
  if (headers) {
    parts.push(headers);
  }
  parts.push(canonicalizedResource(request));
  return parts.join('\n');
}

const INCLUDE_SUBRESOURCES = [
  'accelerate',
  'acl',
  'analytics',
  'cors',
  'delete',
  'inventory',
  'lifecycle',
  'location',
  'logging',
  'metrics',
  'notification',
  'partNumber',
  'policy',
  'requestPayment',
  'restore',
  'tagging',
  'torrent',
  'uploadId',
  'uploads',
  'versionId',
  'versioning',
  'versions',
  'website',
];

const INCLUDE_HEADERS = [
  'response-content-type',
  'response-content-language',
  'response-expires',
  'response-cache-control',
  'response-content-disposition',
  'response-content-encoding',
];

function assembleHeaders(
  headers: Readonly<HeaderBag>,
): string|undefined {
  const sortedHeaderKeys = Object.keys(headers)
    .filter(key => key.match(/^x-amz-/i))
    .sort((a, b) => a.toLowerCase() < b.toLowerCase() ? -1 : 1);
  const parts = sortedHeaderKeys.map(
    (key) => key.toLowerCase() + ':' + String(headers[key])
  );
  return parts.join('\n');
}

function splitQueryString(
  querystring: string,
): Record<string, string> {
  const result: Record<string, string> = {};
  querystring.split('&').map(part => {
    const [key, value] = part.split('=');
    if (value !== undefined) {
      result[key] = decodeURIComponent(value);
    }
  });
  return result;
}

function prepareQuery(
  query: Readonly<QueryParameterBag>,
  querystring: string,
): string {
  return Object.entries({
    ...(querystring ? splitQueryString(querystring) : undefined),
    ...query,
  })
    .filter(([name, _value]) => INCLUDE_SUBRESOURCES.includes(name) || INCLUDE_HEADERS.includes(name))
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => a.name < b.name ? -1 : 1)
    .map((item) => item.value ?
      [item.name, item.value].join('=') :
      item.name
    )
    .join('&');
}

function tryExtractVirtualHostBucket(
  request: Readonly<HttpRequest>,
): string|null {
  // grab <bucket>.s3.whatever.com
  const match = /^([^\.]+)\.s3\..*/.exec(request.hostname);
  if (match) {
    return match[1];
  }
  return null;
}

function canonicalizedResource(
  request: Readonly<HttpRequest>,
): string {
  const [path, querystring] = request.path.split('?');
  let resource = '';
  const virtualHostedBucket = tryExtractVirtualHostBucket(request);
  if (virtualHostedBucket) {
    resource += '/' + virtualHostedBucket;
  }
  resource += path;
  const query = prepareQuery(request.query || {}, querystring);
  if (query) {
    resource += '?' + query;
  }
  return resource;
}
