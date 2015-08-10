# OAuth1AFNetworking
AFNetworking 2.0 overlay, based on AFNetworking 1.0 that use OAuth1. 


You MUST override the 'OAuth1OperationManager' to add :


- (instancetype)init
{
    self = [self initWithBaseURL:[NSURL URLWithString:@"http://YouBaseURL.com"]
                             key:@"YOUR_OAUTH_KEY"
                          secret:@"YOUR_OAUTH_SECRET"];
    
    return self;
}
