# S3-for-GAS-light

AWS の S3 を Google Apps Script上の V8 エンジンで利用するためのライブラリです。
コンパイルした後 clasp を使って Google Apps Script へデプロイして使用します。
通常の AWS SDK for JavaScript は GAS 上では動作しなかったため、このライブラリを作成しました。

[参考元のリポジトリ](https://github.com/eschultink/S3-for-Google-Apps-Script)のコードをベースに、TypeScript で書き直したあと、更に getSignedUrl を追加で実装したものです。

# 使用方法

```bash
npm install s3-for-gas-light
```

使用例:

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

# コントリビューション
バグ報告や機能追加の提案は歓迎します。プルリクエストもお待ちしております。

# LICENSE

このプロジェクトは Apache License 2.0 の下でライセンスされています。

## Licenses of Third-Party Components

This project includes code from the following third-party components:

- **[S3-for-Google-Apps-Script](https://github.com/eschultink/S3-for-Google-Apps-Script)** by Eng Etc LLC
  - License: BSD-3-Clause License
  
- **[AWS SDK for JavaScript](https://github.com/aws/aws-sdk-js)** by Amazon.com, Inc.
  - License: Apache License 2.0

The full text of all licenses can be found in the [LICENSE](LICENSE) file.