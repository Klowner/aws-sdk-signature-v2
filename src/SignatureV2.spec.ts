import {HttpRequest} from '@aws-sdk/protocol-http';
import { fromString } from '@aws-sdk/util-buffer-from';
import { toBase64 } from '@aws-sdk/util-base64-node';
import { signableStringForRequest, SignatureV2 } from './SignatureV2';
import { createHmac } from 'crypto';

// const key = 'GLWVOND9BBWCMX98U9IW';
// const secret = 'p45mGnYHjeK8gZZyWlQw2eLlGFGer0wnYqpu2Bsq';

describe('SignatureV2', () => {
  test('example signature', async () => {

    // const request = new HttpRequest({
    //   method: 'GET',
    //   hostname: 's3.wasabisys.com',
    //   protocol: 'https',
    //   headers: {
    //     'x-amz-date': 'Tue, 03 May 2022 13:58:05 +0000',
    //   }
    // });
    // const signableString = signableStringForRequest(request);
    const key = 'AKIAIOSFODNN7EXAMPLE';
    const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const signableString = `GET
elasticmapreduce.amazonaws.com
/
AWSAccessKeyId=${key}&Action=DescribeJobFlows&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31`;
    const hash = createHmac('sha256', fromString(secret));
    hash.update(signableString);
    const signature = encodeURIComponent(toBase64(hash.digest()));
    expect(signature).toEqual('i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf%2FMj6vPxyYIs%3D');
  });

  test('real signature', async () => {
    const key = 'GLWVOND9BBWCMX98U9IW';
    const secret = 'p45mGnYHjeK8gZZyWlQw2eLlGFGer0wnYqpu2Bsq';
    const request = new HttpRequest({
      method: 'GET',
      hostname: 's3.wasabisys.com',
      headers: {
        'x-amz-date': 'Tue, 03 May 2022 13:58:05 +0000',
      },
      query: {
        partNumber: '20',
        policy: 'public-read',
      }
    });
    const signableString = signableStringForRequest(request);
    const hash = createHmac('sha1', fromString(secret));
    hash.update(signableString);
    const signature = encodeURIComponent(toBase64(hash.digest()));

    console.log(signableString);
  });
});
