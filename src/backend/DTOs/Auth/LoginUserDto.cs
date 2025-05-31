namespace backend.DTOs;

public sealed record LoginUserDto
{
    public required string Email { get; init; }
    public required string Password { get; init; }
}