# SignatureV2 for S3Client

Amazon removed support for signature v2 support in [AWS SDK for JavaScript v3](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/index.html) since it's now mostly deprecated across AWS infrastructure.
Unfortunately, with the widespread adoption of S3 protocols, the need for less secure (but much computationally lighter) v2 signing
is still desirable.

This is an attempt to fill that gap!

## Example
```typescript
import { S3Client } from '@aws-sdk/client-s3';
import { SignatureV2 } from 'aws-sdk-signature-v2';

const s3client = new S3Client({
  signerConstructor: SignatureV2,
  endpoint: '<endpoint>',
  region: '<region>',
  credentials: {
    accessKeyId: '<key_id>',
    secretAccessKey: '<secret>',
  },
});
```

