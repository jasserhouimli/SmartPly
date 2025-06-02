using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using backend.DTOs;
using backend.Entities;
using backend.Settings;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace backend.Services;

public interface ITokenProvider
{
    AccessTokensDto Create(TokenRequest tokenRequest);
    string GenerateAccessToken(TokenRequest tokenRequest);
    string GenerateRefreshToken();
    Task StoreRefreshTokenAsync(User user, string refreshToken, double expirationDays);
    Task<AccessTokensDto?> RefreshTokensAsync(string refreshToken);
}

public sealed class TokenProvider(
    IOptions<JwtAuthOptions> options,
    ApplicationDbContext dbContext) : ITokenProvider
{
    private readonly JwtAuthOptions _jwtOptions = options.Value;

    public AccessTokensDto Create(TokenRequest tokenRequest)
    {
        var accessToken = GenerateAccessToken(tokenRequest);
        var refreshToken = GenerateRefreshToken();

        return new AccessTokensDto(accessToken, refreshToken);
    }

    public string GenerateAccessToken(TokenRequest tokenRequest)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, tokenRequest.UserId),
            new(JwtRegisteredClaimNames.Email, tokenRequest.Email)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtOptions.ExpirationInMinutes),
            SigningCredentials = credentials,
            Issuer = _jwtOptions.Issuer,
            Audience = _jwtOptions.Audience
        };

        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(descriptor);
    }

    public string GenerateRefreshToken()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes);
    }

    public async Task StoreRefreshTokenAsync(User user, string refreshToken, double expirationDays)
    {
        var entity = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = refreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(expirationDays)
        };

        dbContext.RefreshTokens.Add(entity);
        await dbContext.SaveChangesAsync();
    }

    public async Task<AccessTokensDto?> RefreshTokensAsync(string refreshToken)
    {
        var storedToken = await dbContext.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken);

        if (storedToken is null || storedToken.ExpiresAtUtc < DateTime.UtcNow)
            return null;

        var newTokenRequest = new TokenRequest(storedToken.User.Id, storedToken.User.Email!);
        var newTokens = Create(newTokenRequest);

        storedToken.Token = newTokens.RefreshToken;
        storedToken.ExpiresAtUtc = DateTime.UtcNow.AddDays((double)_jwtOptions.RefreshTokenExpirationDays);

        await dbContext.SaveChangesAsync();

        return newTokens;
    }
}
