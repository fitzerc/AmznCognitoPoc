using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Runtime;
using Microsoft.AspNetCore.Identity;
using System.Text;
using Microsoft.Extensions.Configuration;

class Program
{
    static async Task Main(string[] args)
    {
        //Read values from appsettings.json.
        //Need user pool info, iam user info for user with access to said pool, and app client info registered to pool
        var config = new ConfigurationBuilder()
            .AddJsonFile($"appsettings.json")
            .Build();

        var appClientId = config.GetSection("appClientId").Value;
        var userPoolId = config.GetSection("userPoolId").Value;
        var appClientSecret = config.GetSection("appClientSecret").Value;

        var iamUserKey = config.GetSection("iamUserKey").Value;
        var iamUserId = config.GetSection("iamUserId").Value;

        //CognitoUserStore is my object wrapping AmazonCognitoIdentityProviderClient
        //this is a demo, should abstract
        //NOTE: can pass custom region - defaults to US-2
        var userStore = new CognitoUserStore(appClientId, userPoolId, iamUserId, iamUserKey, appClientSecret);

        //Prompt console for name, email, and password
        //username is email
        var user = GetUserFromConsole();

        //Args should be either 'signon' or 'signin'
        switch (args[0])
        {
            case "signup":
                //Ask Cognito to create this user. If setup on the app client in user pool, this should send confirmation code to the email
                var signUpResp = await userStore.CreateAsync(user);
                Console.WriteLine(signUpResp.UserConfirmed ? "Sign-Up Successful" : "Sign-Up Failed");
                break;

            case "signin":
                //Ask cognito to login the user with the given password
                //Returns bearer token, refresh token, etc. if successful
                //Set breakpoint to look at repsonse object
                var signInResp = await userStore.CheckPasswordAsync(user);
                Console.WriteLine(signInResp ? "Sign-In Successful" : "Sign-In Failed");
                break;
            default:
                throw new ArgumentException("signup or signin arg required");
        }
    }

    private static CognitoUser GetUserFromConsole()
    {
        Console.Write("Enter the user's email: ");
        var email = Console.ReadLine();

        Console.Write("Enter the user's name: ");
        var name = Console.ReadLine();

        Console.Write("Enter the user's password: ");
        var password = Console.ReadLine();

        return new CognitoUser
        {
            Password = password,
            Email = email,
            Name = name
        };
    }
}

public class CognitoUserStore
{
    private readonly AmazonCognitoIdentityProviderClient _client;
    private readonly string _clientId;
    private readonly string _clientSecretKey;
    private readonly string _userPoolId;

    public CognitoUserStore(string clientId, string userPoolId, string iamUserKey, string secretKey, string clientSecretKey, RegionEndpoint region = null)
    {
        region ??= RegionEndpoint.USEast2;

        _clientId = clientId;
        _userPoolId = userPoolId;
        _clientSecretKey = clientSecretKey;
        _client = new AmazonCognitoIdentityProviderClient(new BasicAWSCredentials(iamUserKey, secretKey), region);
    }

    public Task<bool> CheckPasswordAsync(CognitoUser user)
    {
        return CheckPasswordAsync(user.Email, user.Password);
    }

    private async Task<bool> CheckPasswordAsync(string userName, string password)
    {
        try
        {
            var authReq = new AdminInitiateAuthRequest
            {
                UserPoolId = _userPoolId,
                ClientId = _clientId,
                AuthFlow = AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
            };
            authReq.AuthParameters.Add("USERNAME", userName);
            authReq.AuthParameters.Add("PASSWORD", password);
            authReq.AuthParameters.Add("SECRET_HASH", CognitoHashCalculator.GetSecretHash(userName, _clientId, _clientSecretKey));

            AdminInitiateAuthResponse authResp = await _client.AdminInitiateAuthAsync(authReq);

            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public async Task<SignUpResponse> CreateAsync(CognitoUser user)
    {
        // Register the user using Cognito
        var signUpRequest = new SignUpRequest
        {
            ClientId = _clientId,
            Password = user.Password,
            Username = user.Email,
            SecretHash = CognitoHashCalculator.GetSecretHash(user.Email, _clientId, _clientSecretKey)
        };

        var emailAttribute = new AttributeType
        {
            Name = "email",
            Value = user.Email
        };

        var nameAttribute = new AttributeType
        {
            Name = "name",
            Value = user.Name
        };

        signUpRequest.UserAttributes.Add(emailAttribute);
        signUpRequest.UserAttributes.Add(nameAttribute);

        return await _client.SignUpAsync(signUpRequest);
    }
}

public class CognitoUser : IdentityUser
{
    public string Password { get; set; }
    public string Name { get; set; }
    public UserStatusType Status { get; set; }
}

public static class CognitoHashCalculator
{
    public static string GetSecretHash(string username, string appClientId, string appSecretKey)
    {
        var dataString = username + appClientId;

        var data = Encoding.UTF8.GetBytes(dataString);
        var key = Encoding.UTF8.GetBytes(appSecretKey);

        return Convert.ToBase64String(HmacSHA256(data, key));
    }

    public static byte[] HmacSHA256(byte[] data, byte[] key)
    {
        using (var shaAlgorithm = new System.Security.Cryptography.HMACSHA256(key))
        {
            var result = shaAlgorithm.ComputeHash(data);
            return result;
        }
    }
}
