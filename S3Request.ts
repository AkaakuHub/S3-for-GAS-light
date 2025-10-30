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

import type { AWSCredentials, AWSError, AWSOptions } from "./types.js";

interface S3Service {
	accessKeyId: string;
	secretAccessKey: string;
	options: AWSOptions;
	logExchange_: (
		request: GoogleAppsScript.URL_Fetch.URLFetchRequest,
		response: GoogleAppsScript.URL_Fetch.HTTPResponse,
	) => string;
	getLastExchangeLog: () => string;
}

export class S3Request {
	private readonly service: S3Service;
	// ここ、Google Apps Scriptのmethod型(小文字put等)を使うとSignatureエラーが出る(本当になんで？)なのでstringでやる
	private httpMethod: string;
	private contentType: string;
	private content: string;
	private bucket: string;
	private objectName: string;
	private headers: { [key: string]: string };
	private readonly date: Date;
	private readonly serviceName: string;
	private readonly region: string;
	private readonly expiresHeader: string;
	private extQueryString: string;
	private lastExchangeLog: string;

	/**
	 * S3リクエストを構築します
	 * @param service S3サービスへの参照
	 */
	constructor(service: S3Service) {
		this.service = service;
		this.httpMethod = "get";
		this.contentType = "";
		this.content = "";
		this.bucket = "";
		this.objectName = "";
		this.headers = {};
		this.date = new Date();
		this.serviceName = "s3";
		this.region = service.options?.region ?? "ap-northeast-1";
		this.expiresHeader = "presigned-expires";
		this.extQueryString = "";
		this.lastExchangeLog = "";
	}

	/**
	 * リクエストのContent-Typeを設定します
	 * @param contentType MIMEタイプ
	 */
	setContentType(contentType: string): this {
		if (typeof contentType !== "string")
			throw new Error("contentType must be passed as a string");
		this.contentType = contentType;
		return this;
	}

	/**
	 * リクエストのContent-Typeを取得します
	 */
	getContentType(): string {
		if (this.contentType) {
			return this.contentType;
		}
		if (this.httpMethod === "put" || this.httpMethod === "post") {
			return "application/x-www-form-urlencoded";
		}
		return "";
	}

	/**
	 * リクエストの内容を設定します
	 * @param content リクエストの内容（文字列）
	 */
	setContent(content: string): this {
		if (typeof content !== "string")
			throw new Error("content must be passed as a string");
		this.content = content;
		return this;
	}

	/**
	 * HTTPメソッドを設定します
	 * @param method HTTPメソッド
	 */
	setHttpMethod(method: string): this {
		if (typeof method !== "string")
			throw new Error("http method must be string");
		this.httpMethod = method;
		return this;
	}

	/**
	 * S3バケット名を設定します
	 * @param bucket S3バケット名
	 */
	setBucket(bucket: string): this {
		if (typeof bucket !== "string")
			throw new Error("bucket name must be string");
		this.bucket = bucket;
		return this;
	}

	/**
	 * オブジェクト名（キー）を設定します
	 * @param objectName オブジェクト名
	 */
	setObjectName(objectName: string): this {
		if (typeof objectName !== "string")
			throw new Error("objectName must be string");
		this.objectName = objectName;
		return this;
	}

	/**
	 * HTTPヘッダーを追加します
	 * @param name ヘッダー名
	 * @param value ヘッダー値
	 */
	addHeader(name: string, value: string): this {
		if (typeof name !== "string") throw new Error("header name must be string");
		if (typeof value !== "string")
			throw new Error("header value must be string");
		this.headers[name] = encodeURIComponent(value);
		return this;
	}

	/**
	 * 署名なしURLを取得します
	 */
	_getUrl(): string {
		return `https://${this.bucket.toLowerCase()}.s3.${this.region}.amazonaws.com/${this.objectName}`;
	}

	/**
	 * リクエストURLを取得します
	 */
	getUrl(): string {
		return this._getUrl() + this.extQueryString;
	}

	/**
	 * S3リクエストを実行してHTTPレスポンスを返します
	 * @param options オプションパラメータ
	 */
	execute(options: AWSOptions = {}): GoogleAppsScript.URL_Fetch.HTTPResponse {
		for (const key in options) {
			const lowerKey = key.toLowerCase();
			if (lowerKey.startsWith("x-amz-") && options[key] !== undefined) {
				this.addHeader(key, String(options[key]));
			}
		}

		// biome-ignore lint/performance/noDelete: <explanation>
		delete this.headers.Authorization;
		// biome-ignore lint/performance/noDelete: <explanation>
		delete this.headers.Date;
		// biome-ignore lint/performance/noDelete: <explanation>
		delete this.headers["X-Amz-Date"];
		this.headers["X-Amz-Content-Sha256"] = this.hexEncodedBodyHash();

		this.headers.Host = this._getUrl().replace(
			/https?:\/\/(.+amazonaws\.com).*/,
			"$1",
		);

		const credentials: AWSCredentials = {
			accessKeyId: this.service.accessKeyId,
			secretAccessKey: this.service.secretAccessKey,
			sessionToken: options.sessionToken,
		};

		this.addAuthorization(credentials, this.date);
		// To avoid conflict with UrlFetchApp#fetch. UrlFetchApp#fetch adds a Host header.
		// biome-ignore lint/performance/noDelete: <explanation>
		delete this.headers.Host;

		const params: GoogleAppsScript.URL_Fetch.URLFetchRequestOptions = {
			method:
				this.httpMethod.toLowerCase() as GoogleAppsScript.URL_Fetch.HttpMethod,
			payload: this.content,
			headers: this.headers,
			muteHttpExceptions: true,
		};

		if (this.getContentType()) {
			params.contentType = this.getContentType();
		}

		const response = UrlFetchApp.fetch(this.getUrl(), params);
		const request = UrlFetchApp.getRequest(this.getUrl(), params);

		this.lastExchangeLog = this.service.logExchange_(request, response);
		if (options.logRequests) {
			Logger.log(this.service.getLastExchangeLog());
		}

		if (options.echoRequestToUrl) {
			UrlFetchApp.fetch(options.echoRequestToUrl, params);
		}

		if (response.getResponseCode() > 299) {
			const error = {} as AWSError;
			error.name = "AwsError";

			try {
				const errorXmlElements = XmlService.parse(response.getContentText())
					.getRootElement()
					.getChildren();
				for (const errorXmlElement of errorXmlElements) {
					let name = errorXmlElement.getName();
					name = name.charAt(0).toLowerCase() + name.slice(1);
					error[name] = errorXmlElement.getText();
				}

				error.toString = function () {
					return `AWS Error - ${this.code}: ${this.message}`;
				};
				error.httpRequestLog = this.service.getLastExchangeLog();
			} catch {
				error.message = `AWS returned HTTP code ${response.getResponseCode()}, but error content could not be parsed.`;
				error.toString = function () {
					return this.message;
				};
				error.httpRequestLog = this.service.getLastExchangeLog();
			}

			throw error;
		}

		return response;
	}

	/**
	 * 認証ヘッダーを追加します
	 * @param credentials AWS認証情報
	 * @param date 日付
	 */
	addAuthorization(credentials: AWSCredentials, date: Date): void {
		const datetime = date.toISOString().replace(/[:|-]|\.\d{3}/g, "");
		if (this.isPresigned()) {
			this.updateForPresigned(credentials, datetime);
		} else {
			this.addHeaders(credentials, datetime);
		}
		this.headers.Authorization = this.authorization(credentials, datetime);
	}

	/**
	 * 認証ヘッダーを追加します
	 * @param credentials AWS認証情報
	 * @param datetime 日時文字列
	 */
	addHeaders(credentials: AWSCredentials, datetime: string): void {
		this.headers["X-Amz-Date"] = datetime;
		if (credentials.sessionToken) {
			this.headers["x-amz-security-token"] = credentials.sessionToken;
		}
	}

	/**
	 * 事前署名付きURLのためのパラメータを更新します
	 * @param credentials AWS認証情報
	 * @param datetime 日時文字列
	 */
	updateForPresigned(credentials: AWSCredentials, datetime: string): void {
		const credString = this.credentialString(datetime);
		const qs: { [key: string]: string } = {
			"X-Amz-Date": datetime,
			"X-Amz-Algorithm": "AWS4-HMAC-SHA256",
			"X-Amz-Credential": `${credentials.accessKeyId}/${credString}`,
			"X-Amz-Expires": this.headers[this.expiresHeader],
			"X-Amz-SignedHeaders": this.signedHeaders(),
		};

		if (credentials.sessionToken) {
			qs["X-Amz-Security-Token"] = credentials.sessionToken;
		}

		if (this.headers["Content-Type"]) {
			qs["Content-Type"] = this.headers["Content-Type"];
		}
		if (this.headers["Content-MD5"]) {
			qs["Content-MD5"] = this.headers["Content-MD5"];
		}
		if (this.headers["Cache-Control"]) {
			qs["Cache-Control"] = this.headers["Cache-Control"];
		}

		for (const key in this.headers) {
			if (key === this.expiresHeader) continue;
			if (this.isSignableHeader(key)) {
				const lowerKey = key.toLowerCase();
				if (lowerKey.startsWith("x-amz-meta-")) {
					qs[lowerKey] = this.headers[key];
				} else if (lowerKey.startsWith("x-amz-")) {
					qs[key] = this.headers[key];
				}
			}
		}

		const sep = this._getUrl().indexOf("?") >= 0 ? "&" : "?";
		const queryParamsToString = (params: {
			[key: string]: string | string[];
		}): string => {
			const items = [];
			for (const key in params) {
				const value = params[key];
				const ename = encodeURIComponent(key);
				if (Array.isArray(value)) {
					const vals = [];
					for (const tempValue in value) {
						vals.push(encodeURIComponent(tempValue));
					}
					vals.sort((a, b) => a.localeCompare(b));
					const joinStr = `&${ename}=`;
					items.push(`${ename}=${vals.join(joinStr)}`);
				} else {
					items.push(`${ename}=${encodeURIComponent(value)}`);
				}
			}
			const sortedItems = items.toSorted((a, b) => a.localeCompare(b));
			return sortedItems.join("&");
		};
		this.extQueryString += sep + queryParamsToString(qs);
	}

	/**
	 * 認証ヘッダー文字列を生成します
	 * @param credentials AWS認証情報
	 * @param datetime 日時文字列
	 */
	authorization(credentials: AWSCredentials, datetime: string): string {
		const parts = [];
		const credString = this.credentialString(datetime);
		parts.push(
			`AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credString}`,
		);
		parts.push(`SignedHeaders=${this.signedHeaders()}`);
		parts.push(`Signature=${this.signature(credentials, datetime)}`);
		return parts.join(", ");
	}

	/**
	 * 署名を計算します
	 * @param credentials AWS認証情報
	 * @param datetime 日時文字列
	 */
	signature(credentials: AWSCredentials, datetime: string): string {
		const signingKey = this.getSignatureKey(
			credentials.secretAccessKey,
			datetime.substring(0, 8),
			this.region,
			this.serviceName,
		);
		const signature = Utilities.computeHmacSha256Signature(
			Utilities.newBlob(this.stringToSign(datetime)).getBytes(),
			signingKey,
		);
		return this.hex(signature);
	}

	/**
	 * バイト配列を16進文字列に変換します
	 * @param values バイト配列
	 */
	hex(values: number[]): string {
		return values.reduce((str, chr) => {
			const hexChr = (chr < 0 ? chr + 256 : chr).toString(16);
			return str + (hexChr.length === 1 ? "0" : "") + hexChr;
		}, "");
	}

	/**
	 * 署名キーを生成します
	 * @param key シークレットキー
	 * @param dateStamp 日付文字列
	 * @param regionName リージョン名
	 * @param serviceName サービス名
	 */
	getSignatureKey(
		key: string,
		dateStamp: string,
		regionName: string,
		serviceName: string,
	): number[] {
		const kDate = Utilities.computeHmacSha256Signature(dateStamp, `AWS4${key}`);
		const kRegion = Utilities.computeHmacSha256Signature(
			Utilities.newBlob(regionName).getBytes(),
			kDate,
		);
		const kService = Utilities.computeHmacSha256Signature(
			Utilities.newBlob(serviceName).getBytes(),
			kRegion,
		);
		const kSigning = Utilities.computeHmacSha256Signature(
			Utilities.newBlob("aws4_request").getBytes(),
			kService,
		);
		return kSigning;
	}

	/**
	 * 署名対象文字列を生成します
	 * @param datetime 日時文字列
	 */
	stringToSign(datetime: string): string {
		const parts = [];
		parts.push("AWS4-HMAC-SHA256");
		parts.push(datetime);
		parts.push(this.credentialString(datetime));
		parts.push(this.hexEncodedHash(this.canonicalString()));
		return parts.join("\n");
	}

	/**
	 * 正規リクエスト文字列を生成します
	 */
	canonicalString(): string {
		const parts = [];
		const [base, search] = this.getUrl().split("?", 2);
		parts.push(this.httpMethod);
		parts.push(this.canonicalUri(base));
		parts.push(this.canonicalQueryString(search || ""));
		parts.push(`${this.canonicalHeaders()}\n`);
		parts.push(this.signedHeaders());
		parts.push(this.hexEncodedBodyHash());
		return parts.join("\n");
	}

	/**
	 * 正規URIを生成します
	 * @param uri URI
	 */
	canonicalUri(uri: string): string {
		const regex = /https?:\/\/(.+)\.s3.*\.amazonaws\.com\/(.+)$/;
		const m = regex.exec(uri);
		const object = m ? m[2] : "";
		return `/${encodeURIComponent(object).replace(/%2F/gi, "/")}`;
	}

	/**
	 * 正規クエリ文字列を生成します
	 * @param values クエリ文字列
	 */
	canonicalQueryString(values: string): string {
		if (!values) return "";
		const parts = [];
		const items = values.split("&");
		for (const item of items) {
			const [key, value] = item.split("=");
			parts.push(
				`${encodeURIComponent(key.toLowerCase())}=${encodeURIComponent(value || "")}`,
			);
		}
		const sortedParts = parts.toSorted((a, b) => a.localeCompare(b));
		return sortedParts.join("&");
	}

	/**
	 * 正規ヘッダー文字列を生成します
	 */
	canonicalHeaders(): string {
		const parts = [];
		for (const item in this.headers) {
			const key = item.toLowerCase();
			if (this.isSignableHeader(key)) {
				const header = `${key}:${this.canonicalHeaderValues(this.headers[item].toString())}`;
				parts.push(header);
			}
		}
		parts.sort((a, b) => a.localeCompare(b));
		return parts.join("\n");
	}

	/**
	 * ヘッダー値を正規化します
	 * @param values ヘッダー値
	 */
	canonicalHeaderValues(values: string): string {
		return values.replace(/\s+/g, " ").trim();
	}

	/**
	 * 署名対象ヘッダーのリストを生成します
	 */
	signedHeaders(): string {
		const keys = [];
		for (const key in this.headers) {
			const lowerKey = key.toLowerCase();
			if (this.isSignableHeader(lowerKey)) {
				keys.push(lowerKey);
			}
		}
		const sortedKeys = keys.toSorted((a, b) => a.localeCompare(b));
		return sortedKeys.join(";");
	}

	/**
	 * 認証情報文字列を生成します
	 * @param datetime 日時文字列
	 */
	credentialString(datetime: string): string {
		return [
			datetime.substring(0, 8),
			this.region,
			this.serviceName,
			"aws4_request",
		].join("/");
	}

	/**
	 * 文字列のSHA256ハッシュを16進数で返します
	 * @param string ハッシュ対象文字列
	 */
	hexEncodedHash(string: string): string {
		return this.hex(
			Utilities.computeDigest(
				Utilities.DigestAlgorithm.SHA_256,
				string,
				Utilities.Charset.UTF_8,
			),
		);
	}

	/**
	 * リクエストボディのSHA256ハッシュを16進数で返します
	 */
	hexEncodedBodyHash(): string {
		if (this.isPresigned() && !this.content.length) {
			return "UNSIGNED-PAYLOAD";
		}
		if (this.headers["X-Amz-Content-Sha256"]) {
			return this.headers["X-Amz-Content-Sha256"];
		}
		return this.hexEncodedHash(this.content || "");
	}

	/**
	 * ヘッダーが署名可能かどうかを判定します
	 * @param key ヘッダー名D
	 */
	isSignableHeader(key: string): boolean {
		const lowerKey = key.toLowerCase();
		if (lowerKey.startsWith("x-amz-")) return true;

		const unsignableHeaders = [
			"authorization",
			"content-type",
			"content-length",
			"user-agent",
			this.expiresHeader,
			"expect",
			"x-amzn-trace-id",
		];
		return unsignableHeaders.indexOf(lowerKey) < 0;
	}

	/**
	 * 事前署名付きURLかどうかを判定します
	 */
	isPresigned(): boolean {
		return !!this.headers[this.expiresHeader];
	}
}
