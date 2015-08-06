//
//  AFHTTPRequestOperationManager.h
//
//
//  Created by Raphaël Pinto on 25/06/2014.
//
// The MIT License (MIT)
// Copyright (c) 2015 Raphael Pinto.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.



#import "AFHTTPRequestOperationManager.h"


typedef NS_ENUM(NSUInteger, AFOAuthSignatureMethod) {
    AFPlainTextSignatureMethod = 1,
    AFHMACSHA1SignatureMethod = 2,
};


@class AFOAuth1Token;


@interface OAuth1OperationManager : AFHTTPRequestOperationManager


@property (nonatomic, assign) AFOAuthSignatureMethod signatureMethod;
@property (readonly, nonatomic, copy) NSString *key;
@property (readonly, nonatomic, copy) NSString *secret;
@property (nonatomic, strong) AFOAuth1Token *accessToken;
@property (nonatomic, copy) NSString *realm;
@property (nonatomic, assign) NSStringEncoding stringEncoding;


- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)clientID
               secret:(NSString *)secret;


- (NSString *)authorizationHeaderForMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters;

- (NSDictionary *)OAuthParameters;
@end
