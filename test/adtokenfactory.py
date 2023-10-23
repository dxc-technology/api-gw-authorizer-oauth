
from msal import PublicClientApplication

class TokenFactory:
    def __init__(self):
        pass
    
    def getToken(self):
        pass
 
class AzureAdTokenFactory(TokenFactory):
    
    app = None
    
    def __init__(self,appId,tenantId,secret):
        authority = f"https://login.microsoftonline.com/{tenantId}"
        self.app=PublicClientApplication(appId,authority=authority)
        
        
    def getToken(self,scope):
        result = self.app.acquire_token_interactive(scopes=[scope])
        if "access_token" in result:
            return result["access_token"]
        print(result)
        return None