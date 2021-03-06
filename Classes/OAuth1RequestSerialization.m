//
//  OAuth1RequestSerialization.m
//
//
//  Created by Raphaël Pinto on 06/08/2015.
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


#import "OAuth1RequestSerialization.h"

#import <CommonCrypto/CommonCrypto.h>

#import "QueryStringPair.h"
#import "AFOAuth1Token.h"


#if !__has_feature(objc_arc)
#error OAuth1RequestSerialization must be built with ARC.
// You can turn on ARC for only OAuth1RequestSerialization files by adding -fobjc-arc to the build phase for each of its files.
#endif


static NSString * const kAFOAuth1Version = @"1.0";


static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFPlainTextSignatureMethod:
            return @"PLAINTEXT";
        case AFHMACSHA1SignatureMethod:
            return @"HMAC-SHA1";
        default:
            return nil;
    }
}


static inline NSString * AFNounce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, uuid);
    
    return (__bridge_transfer NSString *)string;
}


static inline NSString * AFPlainTextSignature(NSString *consumerSecret, NSString *tokenSecret) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *signature = [NSString stringWithFormat:@"%@&%@", consumerSecret, secret];
    return signature;
}


static NSString * AFPercentEscapedStringFromString(NSString *string) {
    static NSString * const kAFCharactersGeneralDelimitersToEncode = @"/?:#[]@"; // does not include "?" or "/" due to RFC 3986 - Section 3.4
    static NSString * const kAFCharactersSubDelimitersToEncode = @"!$&'()*+,;=";
    
    NSMutableCharacterSet * allowedCharacterSet = [[NSCharacterSet URLQueryAllowedCharacterSet] mutableCopy];
    [allowedCharacterSet removeCharactersInString:[kAFCharactersGeneralDelimitersToEncode stringByAppendingString:kAFCharactersSubDelimitersToEncode]];
    
    return [string stringByAddingPercentEncodingWithAllowedCharacters:allowedCharacterSet];
}


@interface OAuth1RequestSerialization ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;


#pragma mark - Private Methods
- (NSString *)authorizationHeaderForMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters;
- (NSDictionary *)OAuthParameters;

@end




@implementation OAuth1RequestSerialization



#pragma mark - String encoding and conversion


+ (NSString*)AFEncodeBase64WithData:(NSData*)_Data
{
    NSUInteger length = [_Data length];
    NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    
    uint8_t *input = (uint8_t *)[_Data bytes];
    uint8_t *output = (uint8_t *)[mutableData mutableBytes];
    
    for (NSUInteger i = 0; i < length; i += 3) {
        NSUInteger value = 0;
        for (NSUInteger j = i; j < (i + 3); j++) {
            value <<= 8;
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }
        
        static uint8_t const kAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        NSUInteger idx = (i / 3) * 4;
        output[idx + 0] = kAFBase64EncodingTable[(value >> 18) & 0x3F];
        output[idx + 1] = kAFBase64EncodingTable[(value >> 12) & 0x3F];
        output[idx + 2] = (i + 1) < length ? kAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
        output[idx + 3] = (i + 2) < length ? kAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
    }
    
    return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}



#pragma mark -
#pragma mark Object Life Cycle Methods



- (id)initWithKey:(NSString *)clientID
           secret:(NSString *)secret
{
    self = [self init];
    
    if (self)
    {
        self.key = clientID;
        self.secret = secret;
        self.signatureMethod = AFHMACSHA1SignatureMethod;
    }
    
    return self;
}



#pragma mark -
#pragma mark oAuth Methods



- (NSDictionary *)OAuthParameters
{
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    parameters[@"oauth_version"] = kAFOAuth1Version;
    parameters[@"oauth_signature_method"] = NSStringFromAFOAuthSignatureMethod(self.signatureMethod);
    parameters[@"oauth_consumer_key"] = self.key;
    parameters[@"oauth_timestamp"] = [@(floor([[NSDate date] timeIntervalSince1970])) stringValue];
    parameters[@"oauth_nonce"] = AFNounce();
    
    if (self.realm) {
        parameters[@"realm"] = self.realm;
    }
    
    return parameters;
}


NSArray * QueryStringPairsFromKeyAndValue(NSString *key, id value) {
    NSMutableArray *mutableQueryStringComponents = [NSMutableArray array];
    
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dictionary = value;
        // Sort dictionary keys to ensure consistent ordering in query string, which is important when deserializing potentially ambiguous sequences, such as an array of dictionaries
        NSSortDescriptor *sortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"description" ascending:YES selector:@selector(caseInsensitiveCompare:)];
        [[[dictionary allKeys] sortedArrayUsingDescriptors:[NSArray arrayWithObject:sortDescriptor]] enumerateObjectsUsingBlock:^(id nestedKey, __unused NSUInteger idx, __unused BOOL *stop) {
            id nestedValue = [dictionary objectForKey:nestedKey];
            if (nestedValue) {
                [mutableQueryStringComponents addObjectsFromArray:QueryStringPairsFromKeyAndValue((key ? [NSString stringWithFormat:@"%@[%@]", key, nestedKey] : nestedKey), nestedValue)];
            }
        }];
    } else if ([value isKindOfClass:[NSArray class]]) {
        NSArray *array = value;
        [array enumerateObjectsUsingBlock:^(id nestedValue, __unused NSUInteger idx, __unused BOOL *stop) {
            [mutableQueryStringComponents addObjectsFromArray:QueryStringPairsFromKeyAndValue([NSString stringWithFormat:@"%@[]", key], nestedValue)];
        }];
    } else if ([value isKindOfClass:[NSSet class]]) {
        NSSet *set = value;
        [set enumerateObjectsUsingBlock:^(id obj, BOOL *stop) {
            [mutableQueryStringComponents addObjectsFromArray:QueryStringPairsFromKeyAndValue(key, obj)];
        }];
    } else {
        [mutableQueryStringComponents addObject:[[QueryStringPair alloc] initWithField:key value:value]];
    }
    return mutableQueryStringComponents;
}


NSString * AFHMACSHA1Signature(NSURL *url,NSString *method, NSDictionary* _HeaderParameters, NSString *consumerSecret, NSString *tokenSecret) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    
    
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", AFPercentEscapedStringFromString(consumerSecret), AFPercentEscapedStringFromString(secret)];
    NSData *secretStringData = [secretString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *queryString = AFPercentEscapedStringFromString([[[[url query] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"]);
    NSString *requestString = [NSString stringWithFormat:@"%@&%@", method, AFPercentEscapedStringFromString([[url absoluteString] componentsSeparatedByString:@"?"][0])];
    
    if ([queryString length] > 0)
    {
        requestString = [requestString stringByAppendingFormat:@"&%@", queryString];
    }
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(_HeaderParameters) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    
    requestString = [requestString stringByAppendingString:@"&"];
    
    int i = 0;
    for (id anObj in sortedComponents)
    {
        if ([anObj isKindOfClass:[NSString class]])
        {
            if (i > 0)
            {
                requestString = [requestString stringByAppendingString:AFPercentEscapedStringFromString(@"&")];
            }
            
            requestString = [requestString stringByAppendingString:AFPercentEscapedStringFromString((NSString*)anObj)];
            
            i++;
        }
    }
    
    NSData *requestStringData = [requestString dataUsingEncoding:NSUTF8StringEncoding];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, [secretStringData bytes], [secretStringData length]);
    CCHmacUpdate(&cx, [requestStringData bytes], [requestStringData length]);
    CCHmacFinal(&cx, digest);
    
    return [OAuth1RequestSerialization AFEncodeBase64WithData:[NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH]];
}


NSArray * QueryStringPairsFromDictionary(NSDictionary *dictionary) {
    return QueryStringPairsFromKeyAndValue(nil, dictionary);
}


NSString * AFQueryStringFromParametersWithEncoding(NSDictionary *parameters) {
    NSMutableArray *mutablePairs = [NSMutableArray array];
    for (QueryStringPair *pair in QueryStringPairsFromDictionary(parameters)) {
        if (![pair.field isEqualToString:@"realm"])
        {
            [mutablePairs addObject:[pair URLEncodedStringValue]];
        }
        else
        {
            [mutablePairs addObject:[NSString stringWithFormat:@"%@=%@", pair.field, pair.value]];
        }
    }
    
    return [mutablePairs componentsJoinedByString:@"&"];
}


- (NSString *)authorizationHeaderForMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters
{
    static NSString * const kAFOAuth1AuthorizationFormatString = @"OAuth %@";
    
    NSMutableDictionary *mutableParameters = parameters ? [parameters mutableCopy] : [NSMutableDictionary dictionary];
    NSMutableDictionary *mutableAuthorizationParameters = [NSMutableDictionary dictionary];
    
    if (self.key && self.secret) {
        [mutableAuthorizationParameters addEntriesFromDictionary:[self OAuthParameters]];
        if (self.accessToken) {
            mutableAuthorizationParameters[@"oauth_token"] = self.accessToken.key;
        }
    }
    
    [mutableParameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if ([key isKindOfClass:[NSString class]] && [key hasPrefix:@"oauth_"]) {
            mutableAuthorizationParameters[key] = obj;
        }
    }];
    
    [mutableParameters addEntriesFromDictionary:mutableAuthorizationParameters];
    mutableAuthorizationParameters[@"oauth_signature"] = [self OAuthSignatureForMethod:method path:path parameters:mutableParameters token:self.accessToken];
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(mutableAuthorizationParameters) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    
    NSMutableArray *mutableComponents = [NSMutableArray array];
    for (NSString *component in sortedComponents) {
        NSArray *subcomponents = [component componentsSeparatedByString:@"="];
        if ([subcomponents count] == 2) {
            [mutableComponents addObject:[NSString stringWithFormat:@"%@=\"%@\"", subcomponents[0], subcomponents[1]]];
        }
    }
    
    return [NSString stringWithFormat:kAFOAuth1AuthorizationFormatString, [mutableComponents componentsJoinedByString:@","]];
}


- (NSString *)OAuthSignatureForMethod:(NSString *)method
                                 path:(NSString *)path
                           parameters:(NSDictionary *)_Parameters
                                token:(AFOAuth1Token *)token
{
    NSURL* lURL = [NSURL URLWithString:path];
    
    NSString *tokenSecret = token ? token.secret : nil;
    
    switch (self.signatureMethod)
    {
        case AFPlainTextSignatureMethod:
            return AFPlainTextSignature(self.secret, tokenSecret);
        case AFHMACSHA1SignatureMethod:
            return AFHMACSHA1Signature(lURL, method, _Parameters, self.secret, tokenSecret);
        default:
            return nil;
    }
}



#pragma mark -
#pragma mark Overrided Methods



- (NSMutableURLRequest *)requestWithMethod:(NSString *)method
                                 URLString:(NSString *)URLString
                                parameters:(id)parameters
                                     error:(NSError *__autoreleasing *)error
{
    NSMutableURLRequest* lMutableRequest = [super requestWithMethod:method
                                                          URLString:URLString
                                                         parameters:parameters
                                                              error:error];
    
    
    NSString* oAuthStr = [self authorizationHeaderForMethod:method
                                                       path:URLString
                                                 parameters:parameters];
    [lMutableRequest setValue:oAuthStr forHTTPHeaderField:@"Authorization"];

    
    return lMutableRequest;
}



- (NSMutableURLRequest *)multipartFormRequestWithMethod:(NSString *)method
                                              URLString:(NSString *)URLString
                                             parameters:(NSDictionary *)parameters
                              constructingBodyWithBlock:(void (^)(id <AFMultipartFormData> formData))block
                                                  error:(NSError *__autoreleasing *)error
{
    NSMutableURLRequest* lMutableRequest = [super multipartFormRequestWithMethod:method
                                                                       URLString:URLString
                                                                      parameters:parameters
                                                       constructingBodyWithBlock:block
                                                                           error:error];
    
    NSString* oAuthStr = [self authorizationHeaderForMethod:method
                                                       path:URLString
                                                 parameters:parameters];
        [lMutableRequest setValue:oAuthStr forHTTPHeaderField:@"Authorization"];
    
    
    return lMutableRequest;
}



#pragma mark -
#pragma mark Public Methods



- (void)clearAccessToken
{
    self.accessToken = nil;
}


- (void)generateAccessTokenWithKey:(NSString*)key
                             token:(NSString*)token
{
    if ([key length] > 0 && [token length] > 0)
    {
        AFOAuth1Token* lOAuth1Token = [[AFOAuth1Token alloc] initWithKey:key
                                                                  secret:token
                                                                 session:nil
                                                              expiration:nil
                                                               renewable:YES];
        self.accessToken = lOAuth1Token;
    }
}




@end
