namespace backend.DTOs;

public sealed record RefreshTokenDto
{
    public required string RefreshToken { get; init; }
}