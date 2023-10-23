# Testing

Running tests requires obtaining valid OAuth 2.0 tokens. The way we do it is by using Azure AD MSAL libraries
and an Azure AD tenant (free subscription) where we register an application capable of requesting and obtaining
tokens.

## Register Application in Azure AD

Go to portal.azure.com register for a free account and create an Azure AD tenant in a free subscription.

- Go to "App Registrations" -> "New registration"
- Choose a name and leave the defautl option selected "Accounts in this organization directory only"
- Skip the "Redirect URI" section and click "Register"

- Go to "Authentication" in the left pane
- In "Advanced Settings" select "Yes" in "Allow public client flows" and click "Save"
- In the same page, click "Add a platform" at the top
- Click on "Mobile and desktop"
- Enter "http://localhost" in "Custom redirects URIs"
- Click "Configure"

- Go to "Certificates and Secrets" and click "New Client Secret"
- Input a description and select any expiration term
- Copy the secret value for later use. You can also come back to this page and copy it later.

- Go to "Expose an API" and click "Add a scope".
- Accept the default value for "Application ID URI"
- Input a name ("default" is a usual one)
- Select "Admins and users" and input some text in "Admin consent display name" and "Admin consent description"
- Click "Add Scope"

# Create Testing Configuration INI Files

For the different tests, multiple configuration files are required. There is a template for each one. You need to 
create a `.ini` file from each template and fill in the following Azure AD values:

```
<<APP ID>>= The Application (client) ID of your registered application
<<TENANT ID>>= The tenant ID of your tenant
<<SECRET>>= The value of the secret created in the application
<<SCOPE>>= The name of the scope

```



