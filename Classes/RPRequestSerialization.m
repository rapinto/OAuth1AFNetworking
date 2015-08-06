//
//  RPRequestSerialization.m
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



#import "RPRequestSerialization.h"
#import "RPHTTPOperationManager.h"



@implementation RPRequestSerialization



#pragma mark -
#pragma mark Overrided Methods



- (NSMutableURLRequest *)requestWithMethod:(NSString *)method
                                 URLString:(NSString *)URLString
                                parameters:(id)parameters
                                     error:(NSError *__autoreleasing *)error
{
    NSMutableURLRequest* lMutableRequest = [super requestWithMethod:method URLString:URLString parameters:parameters error:error];
    
    RPHTTPOperationManager* lOperationManager = [RPHTTPOperationManager sharedInstance];
    
    if ([lOperationManager isKindOfClass:[OAuth1OperationManager class]])
    {
        OAuth1OperationManager* lOAuth1Manager = (OAuth1OperationManager*)lOperationManager;
        
        NSString* oAuthStr = [lOAuth1Manager authorizationHeaderForMethod:method
                                                                     path:URLString
                                                               parameters:parameters];
        [lMutableRequest setValue:oAuthStr forHTTPHeaderField:@"Authorization"];
    }
    
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
    
    RPHTTPOperationManager* lOperationManager = [RPHTTPOperationManager sharedInstance];
    
    if ([lOperationManager isKindOfClass:[OAuth1OperationManager class]])
    {
        OAuth1OperationManager* lOAuth1Manager = (OAuth1OperationManager*)lOperationManager;
        
        NSString* oAuthStr = [lOAuth1Manager authorizationHeaderForMethod:method
                                                                     path:URLString
                                                               parameters:parameters];
        [lMutableRequest setValue:oAuthStr forHTTPHeaderField:@"Authorization"];
        
    }
    
    return lMutableRequest;
}



@end
