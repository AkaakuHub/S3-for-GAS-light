# S3-for-GAS-light

AWS の S3 を Google Apps Script上の V8 エンジンで利用するためのライブラリです。
コンパイルした後 clasp を使って Google Apps Script へデプロイして使用します。

以下のリポジトリ

https://github.com/eschultink/S3-for-Google-Apps-Script

を参考に、TypeScript で書き直したあと、更に getSignedUrl を追加で実装したものです。

# 使用方法

通常のライブラリと同じようにインポートできます。

例:

```typescript
import { S3 } from "./package/S3-for-GAS-light";

const accessKey = "your-access-key";
const secretKey = "your-secret-key";
const region = "ap-northeast-1";
const bucketName = "your-bucket-name";
const objectKey = "your-object-key.json";
const jsonData = JSON.stringify({ key: "value" });

const s3 = new S3(accessKey, secretKey, { region });
s3.putObject(bucketName, objectKey, jsonData);
Logger.log("S3にアップロードしました。");
```

# 更新履歴

2025/3/24 作成
