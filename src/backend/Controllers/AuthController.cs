using System.Security.Claims;
using System.Text.Json;
using backend.DTOs;
using backend.Entities;
using backend.Services;
using backend.Settings;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace backend.Controllers;

[ApiController]
[Route("auth")]
[AllowAnonymous]
public sealed class AuthController(
    UserManager<User> userManager,
    TokenProvider tokenProvider,
    ApplicationDbContext applicationDbContext,
    IOptions<JwtAuthOptions> options,
    IConfiguration configuration) : ControllerBase
{
    private readonly JwtAuthOptions _jwtAuthOptions = options.Value;


    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterUserDto registerUserDto)
    {
        var user = new User
        {
            UserName = registerUserDto.Email,
            Email = registerUserDto.Email
        };

        IdentityResult result = await userManager.CreateAsync(user, registerUserDto.Password);

        if (!result.Succeeded)
        {
            // add Proper Error Handling Later 
            foreach (var e in result.Errors)
                ModelState.AddModelError(e.Code, e.Description);
            return ValidationProblem(ModelState);
        }

        TokenRequest tokenRequest = new TokenRequest(user.Id, registerUserDto.Email);
        AccessTokensDto accessTokens = tokenProvider.Create(tokenRequest);

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = accessTokens.RefreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays)
        };

        applicationDbContext.RefreshTokens.Add(refreshToken);

        await applicationDbContext.SaveChangesAsync();

        return Ok(accessTokens);
    }
    [HttpPost("login")]
    public async Task<ActionResult<AccessTokensDto>> Login(LoginUserDto loginUserDto)
    {
        User? user = await userManager.FindByEmailAsync(loginUserDto.Email);

        if (user is null || !await userManager.CheckPasswordAsync(user, loginUserDto.Password))
        {
            return Unauthorized();
        }

        TokenRequest tokenRequest = new TokenRequest(user.Id, loginUserDto.Email);
        AccessTokensDto accessTokens = tokenProvider.Create(tokenRequest);

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = accessTokens.RefreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays)
        };
        // you are not removing previous refresh Tokens 
        applicationDbContext.RefreshTokens.Add(refreshToken);

        await applicationDbContext.SaveChangesAsync();

        return Ok(accessTokens);
    }
    [HttpPost("refresh")]
    public async Task<ActionResult<AccessTokensDto>> Refresh(RefreshTokenDto refreshTokenDto)
    {
        RefreshToken? refreshToken = await applicationDbContext.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshTokenDto.RefreshToken);

        if (refreshToken is null)
        {
            return Unauthorized();
        }

        if (refreshToken.ExpiresAtUtc < DateTime.UtcNow)
        {
            return Unauthorized();
        }

        var tokenRequest = new TokenRequest(refreshToken.User.Id, refreshToken.User.Email!);
        AccessTokensDto accessTokens = tokenProvider.Create(tokenRequest);

        refreshToken.Token = accessTokens.RefreshToken;
        refreshToken.ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays);

        await applicationDbContext.SaveChangesAsync();

        return Ok(accessTokens);
    }

    [HttpGet("google/authorize")]
    public IActionResult GoogleAuthorize()
    {
        var clientId = configuration["Google:ClientId"];
        var redirectUri = configuration["Google:RedirectUri"];
        var scope = "openid profile email";
        var state = Guid.NewGuid().ToString();

        var authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                     $"client_id={clientId}&" +
                     $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                     $"scope={Uri.EscapeDataString(scope)}&" +
                     $"response_type=code&" +
                     $"state={state}";

        return Ok(new { AuthorizationUrl = authUrl });
    }

    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback(string code, string state, string? error)
    {
        if (!string.IsNullOrEmpty(error))
        {
            return BadRequest($"Google authorization error: {error}");
        }

        if (string.IsNullOrEmpty(code))
        {
            return BadRequest("Authorization code is missing");
        }

        var tokens = await ExchangeCodeForTokens(code);

        var googleUser = await GetGoogleUserInfo(tokens.IdToken);

        var user = await FindOrCreateUser(googleUser);

        var tokenRequest = new TokenRequest(user.Id, user.Email!);
        var accessTokens = tokenProvider.Create(tokenRequest);

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = accessTokens.RefreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays)
        };

        applicationDbContext.RefreshTokens.Add(refreshToken);
        await applicationDbContext.SaveChangesAsync();
        
        var frontendUrl = $"http://localhost:5173?" +
                                $"access_token={accessTokens.AccessToken}&" +
                                $"refresh_token={accessTokens.RefreshToken}";
        Redirect(frontendUrl);
        return Ok(accessTokens);

    }
    private async Task<GoogleTokenResponse> ExchangeCodeForTokens(string code)
    {
        var clientId = configuration["Google:ClientId"];
        var clientSecret = configuration["Google:ClientSecret"];
        var redirectUri = configuration["Google:RedirectUri"];

        using var httpClient = new HttpClient();
        
        var tokenRequest = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("client_id", clientId!),
            new KeyValuePair<string, string>("client_secret", clientSecret!),
            new KeyValuePair<string, string>("redirect_uri", redirectUri!),
            new KeyValuePair<string, string>("grant_type", "authorization_code")
        });

        var response = await httpClient.PostAsync("https://oauth2.googleapis.com/token", tokenRequest);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Failed to exchange code for tokens: {responseContent}");
        }

        var tokenResponse = JsonSerializer.Deserialize<GoogleTokenResponse>(responseContent, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });

        return tokenResponse!;
    }

    private async Task<GoogleUserInfo> GetGoogleUserInfo(string idToken)
    {
        var payload = await GoogleJsonWebSignature.ValidateAsync(idToken);
        
        return new GoogleUserInfo
        {
            Id = payload.Subject,
            Email = payload.Email,
            Name = payload.Name,
            Picture = payload.Picture,
            GivenName = payload.GivenName,
            FamilyName = payload.FamilyName
        };
    }

    private async Task<User> FindOrCreateUser(GoogleUserInfo googleUser)
    {
        var loginInfo = new UserLoginInfo("Google", googleUser.Id, "Google");

        var user = await userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
        
        if (user != null)
        {
            if (user.Email != googleUser.Email)
            {
                user.Email = googleUser.Email;
                user.UserName = googleUser.Email;
                await userManager.UpdateAsync(user);
            }
            return user;
        }

        user = await userManager.FindByEmailAsync(googleUser.Email);
        
        if (user != null)
        {
            var addLoginResult = await userManager.AddLoginAsync(user, loginInfo);
            if (!addLoginResult.Succeeded)
            {
                throw new Exception($"Failed to link Google account: {string.Join(", ", addLoginResult.Errors.Select(e => e.Description))}");
            }
            return user;
        }

        user = new User
        {
            UserName = googleUser.Email,
            Email = googleUser.Email,
            EmailConfirmed = true
        };

        var createResult = await userManager.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            throw new Exception($"Failed to create user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
        }

        var linkResult = await userManager.AddLoginAsync(user, loginInfo);
        if (!linkResult.Succeeded)
        {
            await userManager.DeleteAsync(user);
            throw new Exception($"Failed to link Google account to new user: {string.Join(", ", linkResult.Errors.Select(e => e.Description))}");
        }

        return user;
    }
}