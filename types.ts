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

export interface AWSCredentials {
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken?: string;
}

export interface AWSOptions {
	logRequests?: boolean;
	echoRequestToUrl?: string;
	"x-amz-acl"?: string;
	sessionToken?: string;
	region?: string;
	[key: string]: string | boolean | number | undefined;
}

export interface AWSError extends Error {
	name: string;
	code?: string;
	message: string;
	httpRequestLog?: string;
	toString(): string;
	[key: string]: unknown;
}
