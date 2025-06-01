using System.Text;
using System.Text.Json;
using backend.DTOs;
using backend.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace backend.Controllers;

[ApiController]
[Route("gmail")]
[Authorize]
public class GmailController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GmailController> _logger;

    public GmailController(
        UserManager<User> userManager,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ILogger<GmailController> logger)
    {
        _userManager = userManager;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    [HttpGet("messages")]
    public async Task<IActionResult> GetEmails()
    {
        try
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized("User not authenticated");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found");
            }

            var googleAccessToken = await GetAuthenticationTokenAsync(user);
            if (string.IsNullOrEmpty(googleAccessToken))
            {
                return Unauthorized("No valid Google token found. Please authenticate with Google first.");
            }

            var emails = await GetGmailMessages(googleAccessToken);
            return Ok(emails);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving Gmail messages");
            return StatusCode(500, $"Error retrieving emails: {ex.Message}");
        }
    }

    private async Task<string> GetAuthenticationTokenAsync(User user)
    {
        try
        {
            var accessToken = await _userManager.GetAuthenticationTokenAsync(user, "Google", "access_token");
            var expiresAtStr = await _userManager.GetAuthenticationTokenAsync(user, "Google", "expires_at");

            if (!string.IsNullOrEmpty(accessToken) && !string.IsNullOrEmpty(expiresAtStr))
            {
                if (DateTime.TryParse(expiresAtStr, out var expiresAt))
                {
                    var bufferTimespan = TimeSpan.FromMinutes(5);
                    var currentTimeWithBuffer = DateTime.UtcNow.Add(bufferTimespan);

                    if (expiresAt > currentTimeWithBuffer)
                    {
                        _logger.LogInformation("Using existing valid Google token that expires at {ExpiryTime}", expiresAt);
                        return accessToken;
                    }

                    _logger.LogInformation("Google token expired or about to expire at {ExpiryTime}, refreshing", expiresAt);
                }
            }

            var refreshToken = await _userManager.GetAuthenticationTokenAsync(user, "Google", "refresh_token");
            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("No refresh token found for user {UserId}", user.Id);
                return null;
            }

            var newTokens = await RefreshGoogleTokenAsync(refreshToken);
            if (newTokens != null)
            {
                await _userManager.SetAuthenticationTokenAsync(user, "Google", "access_token", newTokens.AccessToken);

                var newExpiresAt = DateTime.UtcNow.AddSeconds(newTokens.ExpiresIn);
                await _userManager.SetAuthenticationTokenAsync(user, "Google", "expires_at", newExpiresAt.ToString("O"));

                _logger.LogInformation("Successfully refreshed Google token, new expiry at {ExpiryTime}", newExpiresAt);
                return newTokens.AccessToken;
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting authentication token");
            return null;
        }
    }

    private async Task<GoogleTokenResponse> RefreshGoogleTokenAsync(string refreshToken)
    {
        try
        {
            var clientId = _configuration["Google:ClientId"];
            var clientSecret = _configuration["Google:ClientSecret"];

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                _logger.LogError("Missing Google Client ID or Client Secret in configuration");
                return null;
            }

            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.Timeout = TimeSpan.FromSeconds(30);

            var tokenRequest = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("grant_type", "refresh_token")
            });

            _logger.LogInformation("Attempting to refresh Google access token");
            var response = await httpClient.PostAsync("https://oauth2.googleapis.com/token", tokenRequest);

            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to refresh Google token: Status {StatusCode}, Response: {ErrorContent}",
                    response.StatusCode, responseContent);
                return null;
            }

            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                PropertyNameCaseInsensitive = true
            };

            var tokenResponse = JsonSerializer.Deserialize<GoogleTokenResponse>(responseContent, options);

            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                _logger.LogError("Received invalid token response from Google");
                return null;
            }

            _logger.LogInformation("Successfully refreshed Google access token");
            return tokenResponse;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error occurred while refreshing Google token");
            return null;
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to parse Google token response");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during Google token refresh");
            return null;
        }
    }

    private async Task<List<EmailMessageDto>> GetGmailMessages(string accessToken)
    {
        try
        {
            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);


            var listResponse = await httpClient.GetAsync("https://www.googleapis.com/gmail/v1/users/me/messages?maxResults=50");

            if (!listResponse.IsSuccessStatusCode)
            {
                var errorContent = await listResponse.Content.ReadAsStringAsync();
                _logger.LogError("Failed to list Gmail messages: Status {StatusCode}, Response: {Response}",
                    listResponse.StatusCode, errorContent);
                throw new Exception($"Failed to list messages: {listResponse.StatusCode}");
            }

            var listContent = await listResponse.Content.ReadAsStringAsync();
            _logger.LogDebug("Gmail API List Response: {Response}", listContent);

            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };

            var messagesListResponse = JsonSerializer.Deserialize<GmailMessagesListResponse>(listContent, options);

            if (messagesListResponse?.Messages == null)
            {
                _logger.LogInformation("No messages found in Gmail account");
                return new List<EmailMessageDto>();
            }

            var emails = new List<EmailMessageDto>();


            foreach (var message in messagesListResponse.Messages)
            {
                try
                {
                    var detailResponse = await httpClient.GetAsync($"https://www.googleapis.com/gmail/v1/users/me/messages/{message.Id}");
                    if (!detailResponse.IsSuccessStatusCode)
                    {
                        var errorDetail = await detailResponse.Content.ReadAsStringAsync();
                        _logger.LogWarning("Failed to get message details for ID: {MessageId}, Status: {StatusCode}, Response: {Response}",
                            message.Id, detailResponse.StatusCode, errorDetail);
                        continue;
                    }

                    var detailContent = await detailResponse.Content.ReadAsStringAsync();
                    var messageDetail = JsonSerializer.Deserialize<GmailMessageDetail>(detailContent, options);

                    if (messageDetail != null)
                    {
                        var email = new EmailMessageDto
                        {
                            Id = messageDetail.Id,
                            Subject = GetHeaderValue(messageDetail, "Subject"),
                            From = GetHeaderValue(messageDetail, "From"),
                            Date = GetHeaderValue(messageDetail, "Date"),
                            Snippet = messageDetail.Snippet ?? string.Empty
                        };


                        if (messageDetail.Payload?.Parts != null)
                        {
                            foreach (var part in messageDetail.Payload.Parts)
                            {
                                if (part.MimeType == "text/plain" && !string.IsNullOrEmpty(part.Body?.Data))
                                {
                                    try
                                    {
                                        email.Body = DecodeBase64UrlSafe(part.Body.Data);
                                        break;
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogWarning("Failed to decode email body: {Error}", ex.Message);
                                        email.Body = "[Body could not be decoded]";
                                    }
                                }
                            }
                        }
                        else if (messageDetail.Payload?.Body?.Data != null)
                        {
                            try
                            {
                                email.Body = DecodeBase64UrlSafe(messageDetail.Payload.Body.Data);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning("Failed to decode email body: {Error}", ex.Message);
                                email.Body = "[Body could not be decoded]";
                            }
                        }

                        emails.Add(email);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing email message {MessageId}", message.Id);

                }
            }

            return emails;
        }
        catch (JsonException jsonEx)
        {
            _logger.LogError(jsonEx, "JSON deserialization error in GetGmailMessages");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in GetGmailMessages");
            throw;
        }
    }

    private string GetHeaderValue(GmailMessageDetail message, string headerName)
    {
        try
        {
            return message.Payload?.Headers?.FirstOrDefault(h =>
                string.Equals(h.Name, headerName, StringComparison.OrdinalIgnoreCase))?.Value ?? string.Empty;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting header {HeaderName}", headerName);
            return string.Empty;
        }
    }

    private string DecodeBase64UrlSafe(string base64UrlSafe)
    {
        if (string.IsNullOrEmpty(base64UrlSafe))
        {
            return string.Empty;
        }

        try
        {
            string base64 = base64UrlSafe.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            byte[] bytes = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to decode base64 string");
            return "[Encoding error]";
        }
    }
}
