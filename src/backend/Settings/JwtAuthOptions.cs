namespace backend.Settings;

public sealed class JwtAuthOptions
{
    public string Issuer { get; init; }
    public string Audience { get; init; }
    public string Key { get; init; }
    public double ExpirationInMinutes { get; init; }
    public double RefreshTokenExpirationDays { get; init; }
}