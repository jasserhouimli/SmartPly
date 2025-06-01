namespace backend.DTOs ;

public sealed record GoogleTokenResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string IdToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
}