using backend.DTOs;
using backend.Entities;
using backend.Exceptions;
using backend.Results;
using backend.Settings;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace backend.Services;

public interface IAuthService
{
    Task<AuthResult> RegisterAsync(RegisterUserDto dto);
    Task<AuthResult> LoginAsync(LoginUserDto dto);
    Task<AuthResult> RefreshTokenAsync(RefreshTokenDto dto);
    string GetGoogleAuthorizationUrl();
    Task<string> HandleGoogleCallbackAsync(string code, string state, string? error);
}

public sealed class AuthService(
    UserManager<User> userManager,
    ITokenProvider tokenProvider,
    ApplicationDbContext db,
    IOptions<JwtAuthOptions> options,
    IGoogleProvider googleProvider,
    IConfiguration configuration) : IAuthService
{
    private readonly JwtAuthOptions _jwtOptions = options.Value;

    public async Task<AuthResult> RegisterAsync(RegisterUserDto dto)
    {
        var user = new User
        {
            UserName = dto.Email,
            Email = dto.Email
        };

        var result = await userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
        {
            var error = string.Join(", ", result.Errors.Select(e => e.Description));
            return new AuthFailure(error);
        }

        var tokens = tokenProvider.Create(new TokenRequest(user.Id, user.Email!));
        await tokenProvider.StoreRefreshTokenAsync(user, tokens.RefreshToken, _jwtOptions.RefreshTokenExpirationDays);

        return new AuthSuccess(tokens);
    }

    public async Task<AuthResult> LoginAsync(LoginUserDto dto)
    {
        var user = await userManager.FindByEmailAsync(dto.Email);
        if (user == null || !await userManager.CheckPasswordAsync(user, dto.Password))
        {
            return new AuthFailure("Invalid credentials.");
        }

        var tokens = tokenProvider.Create(new TokenRequest(user.Id, user.Email!));
        await tokenProvider.StoreRefreshTokenAsync(user, tokens.RefreshToken, _jwtOptions.RefreshTokenExpirationDays);

        return new AuthSuccess(tokens);
    }

    public async Task<AuthResult> RefreshTokenAsync(RefreshTokenDto dto)
    {
        var newTokens = await tokenProvider.RefreshTokensAsync(dto.RefreshToken);
        return newTokens == null
            ? new AuthFailure("Refresh token invalid or expired.")
            : new AuthSuccess(newTokens);
    }

    public string GetGoogleAuthorizationUrl()
    {
        return googleProvider.GetAuthorizationUrl();
    }

    public async Task<string> HandleGoogleCallbackAsync(string code, string state, string? error)
    {
        if (!string.IsNullOrEmpty(error))
            throw new AuthException($"Google authorization error: {error}");

        if (string.IsNullOrEmpty(code))
            throw new AuthException("Authorization code is missing");

        var tokens = await googleProvider.ExchangeCodeForTokens(code);
        var googleUser = await googleProvider.GetGoogleUserInfo(tokens.IdToken);
        var user = await FindOrCreateUserAsync(googleUser);

        await googleProvider.StoreGoogleTokens(user, tokens);

        var accessTokens = tokenProvider.Create(new TokenRequest(user.Id, user.Email!));
        await tokenProvider.StoreRefreshTokenAsync(user, accessTokens.RefreshToken, _jwtOptions.RefreshTokenExpirationDays);

        return $"{configuration["FrontEnd:BaseUrl"]}?" +
               $"access_token={accessTokens.AccessToken}&" +
               $"refresh_token={accessTokens.RefreshToken}";
    }

    private async Task<User> FindOrCreateUserAsync(GoogleUserInfo googleUser)
    {
        var loginInfo = new UserLoginInfo("Google", googleUser.Id, "Google");

        var user = await userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
        if (user != null)
            return user;

        user = await userManager.FindByEmailAsync(googleUser.Email);
        if (user != null)
        {
            var result = await userManager.AddLoginAsync(user, loginInfo);
            if (!result.Succeeded)
                throw new UserLinkingException(string.Join(", ", result.Errors.Select(e => e.Description)));

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
            throw new UserCreationException(string.Join(", ", createResult.Errors.Select(e => e.Description)));

        var linkResult = await userManager.AddLoginAsync(user, loginInfo);
        if (!linkResult.Succeeded)
        {
            await userManager.DeleteAsync(user);
            throw new UserLinkingException(string.Join(", ", linkResult.Errors.Select(e => e.Description)));
        }

        return user;
    }
}
