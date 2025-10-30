/**
 * Copyright (c) 2025, AkaakuHub
 *
 * This file is part of the “S3-for-GAS-light” library.
 * It contains modified and newly implemented code based on:
 *   - AWS SDK (Copyright 2012-2017 Amazon.com, Inc. or its affiliates)  
 *     Licensed under the Apache License, Version 2.0.
 *   - S3-for-Google-Apps-Script (Copyright 2014-2015 Eng Etc LLC)  
 *     Licensed under the BSD-3-Clause License.
 *
 * Modifications made by AkaakuHub on 2025-3-24
 *
 * Licensed under the Apache License, Version 2.0 (the “License”);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ---------------------------------------------------------------------------
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, of the S3-for-Google-Apps-Script component (BSD-3-Clause)
 * are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Eng Etc LLC, S3-for-Google-Apps-Script, nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ENG ETC LLC BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import { S3Request } from "./S3Request.js";
import type { AWSOptions } from "./types.js";

export class S3 {
	accessKeyId: string;
	secretAccessKey: string;
	options: AWSOptions;
	lastExchangeLog: string;

	/**
	 * S3サービスを構築します
	 * @param accessKeyId AWSアクセスキーID
	 * @param secretAccessKey AWSシークレットアクセスキー
	 * @param options オプション
	 */
	constructor(
		accessKeyId: string,
		secretAccessKey: string,
		options: AWSOptions = {},
	) {
		if (typeof accessKeyId !== "string")
			throw new Error("Must pass accessKeyId to S3 constructor");
		if (typeof secretAccessKey !== "string")
			throw new Error("Must pass secretAcessKey to S3 constructor");

		this.accessKeyId = accessKeyId;
		this.secretAccessKey = secretAccessKey;
		this.options = options;
		this.lastExchangeLog = "";
	}

	/**
	 * S3バケットを作成します
	 * @param bucket バケット名
	 * @param options オプションパラメータ
	 */
	createBucket(bucket: string, options: AWSOptions = {}): void {
		const request = new S3Request(this);
		request.setHttpMethod("PUT");

		// UrlFetchAppが適切なContent-Typeを設定するため明示的に設定
		request.setContentType("text/plain");

		// ACL設定をサポート
		if (typeof options["x-amz-acl"] === "undefined") {
			options["x-amz-acl"] = "private";
		}
		request.addHeader("x-amz-acl", options["x-amz-acl"]);

		request.setBucket(bucket);
		request.execute(options);
	}

	/**
	 * S3バケットを削除します
	 * @param bucket バケット名
	 * @param options オプションパラメータ
	 */
	deleteBucket(bucket: string, options: AWSOptions = {}): void {
		const request = new S3Request(this);
		request.setHttpMethod("DELETE");

		request.setBucket(bucket);
		request.execute(options);
	}

	/**
	 * オブジェクトをS3バケットにアップロードします
	 * @param bucket バケット名
	 * @param objectName オブジェクト名（キー）
	 * @param object アップロードするオブジェクト
	 * @param options オプションパラメータ
	 */
	putObject(
		bucket: string,
		objectName: string,
		object: GoogleAppsScript.Base.Blob | object | string | number | boolean,
		options: AWSOptions = {},
	): void {
		const request = new S3Request(this);
		request.setHttpMethod("PUT");
		request.setBucket(bucket);
		request.setObjectName(objectName);

		// Define a type for blob-like objects
		type BlobLike = {
			copyBlob: () => GoogleAppsScript.Base.Blob;
			getDataAsString: () => string;
			getContentType: () => string;
		};

		let objectBlob: GoogleAppsScript.Base.Blob;

		// Check if object is a primitive type (string, number, boolean)
		if (object === null || object === undefined || typeof object !== "object") {
			// プリミティブ型の場合、文字列に変換してBlobにラップ
			const contentStr = String(object);
			objectBlob = Utilities.newBlob(contentStr, "text/plain");
			objectBlob.setName(objectName);
		}
		// Blobのような振る舞いをするかチェック
		else if (
			!(
				"copyBlob" in object &&
				typeof (object as BlobLike).copyBlob === "function" &&
				"getDataAsString" in object &&
				typeof (object as BlobLike).getDataAsString === "function" &&
				"getContentType" in object &&
				typeof (object as BlobLike).getContentType === "function"
			)
		) {
			// 通常のオブジェクトの場合、JSONとしてシリアライズ
			objectBlob = Utilities.newBlob(
				JSON.stringify(object),
				"application/json",
			);
			objectBlob.setName(objectName);
		} else {
			// Blobオブジェクトの場合
			objectBlob = object;
		}

		request.setContent(objectBlob.getDataAsString());
		request.setContentType(
			objectBlob.getContentType() ?? "application/octet-stream",
		);

		request.execute(options);
	}

	/**
	 * S3バケットからオブジェクトを取得します
	 * @param bucket バケット名
	 * @param objectName オブジェクト名（キー）
	 * @param options オプションパラメータ
	 * @returns 取得したオブジェクト（Blob または JSONオブジェクト）
	 */
	getObject(
		bucket: string,
		objectName: string,
		options: AWSOptions = {},
	): GoogleAppsScript.Base.Blob | Record<string, unknown> | string | null {
		const request = new S3Request(this);
		request.setHttpMethod("GET");

		request.setBucket(bucket);
		request.setObjectName(objectName);
		try {
			const responseBlob = request.execute(options).getBlob();

			// コンテンツタイプに応じて適切な形式で返す
			const contentType = responseBlob.getContentType();

			// JSONの場合はパースしてオブジェクトとして返す
			if (contentType === "application/json") {
				return JSON.parse(responseBlob.getDataAsString());
			}

			// テキストの場合は文字列として返す
			if (contentType === "text/plain") {
				return responseBlob.getDataAsString();
			}

			// その他の形式はBlobとして返す
			return responseBlob;
		} catch (e: unknown) {
			const error = e as { name: string; code?: string };
			if (error.name === "AwsError" && error.code === "NoSuchKey") {
				return null;
			}
			// その他のエラーは再スロー
			throw e;
		}
	}

	/**
	 * S3バケットからオブジェクトを削除します
	 * @param bucket バケット名
	 * @param objectName オブジェクト名（キー）
	 * @param options オプションパラメータ
	 */
	deleteObject(
		bucket: string,
		objectName: string,
		options: AWSOptions = {},
	): void {
		const request = new S3Request(this);
		request.setHttpMethod("DELETE");

		request.setBucket(bucket);
		request.setObjectName(objectName);
		request.execute(options);
	}

	/**
	 * 署名付きURLを生成します
	 * @param region リージョン
	 * @param bucket バケット名
	 * @param key オブジェクト名（キー）
	 * @param method HTTPメソッド（デフォルトはPUT）
	 * @param credentials 認証情報
	 * @param expiresIn 有効期限（秒単位、デフォルトは3600秒）
	 * @return 署名付きURL
	 * @throws エラーが発生した場合
	 */
	getSignedUrl(params: {
		region: string;
		bucket: string;
		key: string;
		method?: string;
		credentials: {
			accessKeyId: string;
			secretAccessKey: string;
		};
		expiresIn?: number;
	}): string {
		const {
			region,
			bucket,
			key,
			credentials,
			expiresIn = 3600,
			method = "PUT",
		} = params;

		// S3署名リクエスト用のパラメータを設定
		const endpoint = `${bucket}.s3.${region}.amazonaws.com`;
		const datetime = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
		const date = datetime.substring(0, 8);

		// 必要な署名コンポーネントを作成
		const service = "s3";
		const algorithm = "AWS4-HMAC-SHA256";
		const credentialScope = `${date}/${region}/${service}/aws4_request`;

		// クエリパラメータの作成
		const query: Record<string, string> = {
			"X-Amz-Algorithm": algorithm,
			"X-Amz-Credential": `${credentials.accessKeyId}/${credentialScope}`,
			"X-Amz-Date": datetime,
			"X-Amz-Expires": expiresIn.toString(),
			"X-Amz-SignedHeaders": "host",
		};

		// リクエストの正規化と署名の生成
		const canonicalRequest = createCanonicalRequest(
			method,
			`/${key}`,
			query,
			endpoint,
		);
		const stringToSign = createStringToSign(
			datetime,
			region,
			service,
			canonicalRequest,
		);
		const signature = createSignature(
			credentials.secretAccessKey,
			date,
			region,
			service,
			stringToSign,
		);

		// 署名を含めた最終的なクエリパラメータの生成
		query["X-Amz-Signature"] = signature;

		// 最終的なURLを生成
		const queryString = Object.keys(query)
			.sort((a, b) => a.localeCompare(b))
			.map(
				(key) => `${encodeURIComponent(key)}=${encodeURIComponent(query[key])}`,
			)
			.join("&");

		return `https://${endpoint}/${encodeURIComponent(key)}?${queryString}`;
	}

	/**
	 * 最後のHTTP交換のログを取得します
	 */
	getLastExchangeLog(): string {
		return this.lastExchangeLog;
	}

	/**
	 * HTTPリクエスト/レスポンスに関するログエントリをフォーマットします
	 * @param request UrlFetchApp.getRequest()からのリクエストオブジェクト
	 * @param response UrlFetchAppからのレスポンスオブジェクト
	 */
	logExchange_(
		request: GoogleAppsScript.URL_Fetch.URLFetchRequestOptions,
		response: GoogleAppsScript.URL_Fetch.HTTPResponse,
	): string {
		let logContent = "";
		logContent += "\n-- REQUEST --\n";
		// Convert request to a Record to allow for string indexing
		const requestRecord = request as Record<string, unknown>;
		for (const i in request) {
			if (
				typeof requestRecord[i] === "string" &&
				requestRecord[i].length > 1000
			) {
				// 読みやすさのために長いコンテンツを切り詰める
				requestRecord[i] = `${requestRecord[i].slice(0, 1000)} ... [TRUNCATED]`;
			}
			logContent += Utilities.formatString("\t%s: %s\n", i, requestRecord[i]);
		}

		logContent += "-- RESPONSE --\n";
		logContent += `HTTP Status Code: ${response.getResponseCode()}\n`;
		logContent += "Headers:\n";

		const headers = response.getHeaders() as Record<string, string>;
		for (const i in headers) {
			logContent += Utilities.formatString("\t%s: %s\n", i, headers[i]);
		}
		logContent += `Body:\n${response.getContentText()}`;
		this.lastExchangeLog = logContent;
		return logContent;
	}
}

/**
 * S3サービスのインスタンスを返します
 * @param accessKeyId AWSアクセスキーID
 * @param secretAccessKey AWSシークレットアクセスキー
 * @param options オプション
 * @returns S3インスタンス
 */
export function getInstance(
	accessKeyId: string,
	secretAccessKey: string,
	options: AWSOptions = {},
): S3 {
	return new S3(accessKeyId, secretAccessKey, options);
}

/**
 * 正規リクエストを生成します
 */
function createCanonicalRequest(
	method: string,
	path: string,
	query: Record<string, string>,
	hostname: string,
): string {
	const canonicalHeaders = `host:${hostname}\n`;
	const payloadHash = "UNSIGNED-PAYLOAD";
	const canonicalQueryString = Object.keys(query)
		.sort((a, b) => a.localeCompare(b))
		.map(
			(key) => `${encodeURIComponent(key)}=${encodeURIComponent(query[key])}`,
		)
		.join("&");

	const canonicalRequest = [
		method,
		path,
		canonicalQueryString,
		canonicalHeaders,
		"host",
		payloadHash,
	].join("\n");

	return canonicalRequest;
}

/**
 * 署名対象の文字列を生成します
 */
function createStringToSign(
	datetime: string,
	region: string,
	service: string,
	canonicalRequest: string,
): string {
	const hashedRequest = hash(canonicalRequest);
	const scope = `${datetime.substring(0, 8)}/${region}/${service}/aws4_request`;

	return ["AWS4-HMAC-SHA256", datetime, scope, hashedRequest].join("\n");
}

/**
 * 署名を計算します
 */
function createSignature(
	secretKey: string,
	date: string,
	region: string,
	service: string,
	stringToSign: string,
): string {
	// 署名キーを生成
	const kSecret = `AWS4${secretKey}`;
	const kDate = hmacSha256(kSecret, date);
	const kRegion = hmacSha256FromBytes(kDate, region);
	const kService = hmacSha256FromBytes(kRegion, service);
	const kSigning = hmacSha256FromBytes(kService, "aws4_request");

	// 最終的な署名を生成
	return hmacSha256Hex(kSigning, stringToSign);
}

/**
 * 文字列のSHA256ハッシュを計算します
 */
function hash(value: string): string {
	const hash = Utilities.computeDigest(
		Utilities.DigestAlgorithm.SHA_256,
		value,
	);
	return toHex(hash);
}

/**
 * HMAC-SHA256を計算します (文字列キー)
 */
function hmacSha256(key: string, value: string): number[] {
	return Utilities.computeHmacSha256Signature(
		Utilities.newBlob(value).getBytes(),
		Utilities.newBlob(key).getBytes(),
	);
}

/**
 * HMAC-SHA256を計算します (バイト配列キー)
 */
function hmacSha256FromBytes(key: number[], value: string): number[] {
	return Utilities.computeHmacSha256Signature(
		Utilities.newBlob(value).getBytes(),
		key,
	);
}

/**
 * HMAC-SHA256を計算して16進数で返します
 */
function hmacSha256Hex(key: number[], value: string): string {
	const signature = hmacSha256FromBytes(key, value);
	return toHex(signature);
}

/**
 * バイト配列を16進数文字列に変換します
 */
function toHex(bytes: number[]): string {
	return bytes
		.map((byte) => {
			const hex = (byte & 0xff).toString(16);
			return hex.length === 1 ? `0${hex}` : hex;
		})
		.join("");
}
