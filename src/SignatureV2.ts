import {buildQueryString} from "@aws-sdk/querystring-builder";
import {prepareRequest} from "@aws-sdk/signature-v4";
import type {
  Credentials,
  HashConstructor,
  HttpRequest,
  Provider,
  RequestSigner,
  RequestSigningArguments,
} from "@aws-sdk/types";
import { normalizeProvider } from "@aws-sdk/util-middleware";
import { toBase64 } from "@aws-sdk/util-base64-node";

export interface SignatureV2Init {
  service: string;
  credentials: Credentials | Provider<Credentials>;
  sha256: HashConstructor;
}

export class SignatureV2 implements RequestSigner {
  private readonly credentialProvider: Provider<Credentials>;
  private readonly sha256: HashConstructor;
  private readonly toBase64 = toBase64;

  constructor({
    credentials,
    sha256,
  }: SignatureV2Init) {
    this.credentialProvider = normalizeProvider(credentials);
    this.sha256 = sha256;
  }

  async sign(stringToSign: string): Promise<string>;
  async sign(requestToSign: HttpRequest): Promise<HttpRequest>;
  async sign(toSign: string|HttpRequest) {
    if (typeof toSign === 'string') {
      return this.signString(toSign);
    }
    return this.signRequest(toSign);
  }


  async signString(
    stringToHash: string,
  ): Promise<string> {
    const credentials = await this.credentialProvider();
    const hash = new this.sha256(credentials.secretAccessKey);
    hash.update(stringToHash);
    const signature = this.toBase64(await hash.digest());
    return signature;
  }

  async signRequest(
    requestToSign: HttpRequest,
    {}: RequestSigningArguments = {},
  ): Promise<HttpRequest> {
    const request = prepareRequest(requestToSign);
    const stringToSign = signableStringForRequest(requestToSign);
    const signature = await this.signString(stringToSign);
    request.query = {
      ...request.query,
      'Signature': encodeURIComponent(signature),
    };
    return request;
  }
}

const portNumberIfNonStandard = (port?: number) =>
  (port === 80 || port === 443) ? (':' + port) : '';

function signableStringForRequest(
  request: HttpRequest,
): string {
  return [
    request.method,
    request.hostname.toLowerCase() + portNumberIfNonStandard(request.port),
    encodeURI(request.path),
    buildQueryString(request.query ?? {}),
  ].join('\n');
}
