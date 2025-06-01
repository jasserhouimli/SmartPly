public class GmailMessagesListResponse
{
    public List<GmailMessageId> Messages { get; set; }
    public string NextPageToken { get; set; }
}

public class GmailMessageId
{
    public string Id { get; set; }
    public string ThreadId { get; set; }
}

public class GmailMessageDetail
{
    public string Id { get; set; } = string.Empty;
    public string ThreadId { get; set; } = string.Empty;
    public string? Snippet { get; set; }
    public int SizeEstimate { get; set; }
    public GmailMessagePayload? Payload { get; set; }
}

public class GmailMessagePayload
{
    public string MimeType { get; set; }
    public List<GmailMessageHeader> Headers { get; set; }
    public GmailMessageBodyPart Body { get; set; }
    public List<GmailMessagePart> Parts { get; set; }
}

public class GmailMessageHeader
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

public class GmailMessageBodyPart
{
    public string Data { get; set; }
    public int Size { get; set; }
}

public class GmailMessagePart
{
    public string PartId { get; set; }
    public string MimeType { get; set; }
    public string Filename { get; set; }
    public GmailMessageBodyPart Body { get; set; }
    public List<GmailMessageHeader> Headers { get; set; }
    public List<GmailMessagePart> Parts { get; set; }
}

public class EmailMessageDto
{
    public string Id { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string From { get; set; } = string.Empty;
    public string Date { get; set; } = string.Empty;
    public string Snippet { get; set; } = string.Empty;
    public string? Body { get; set; }
}
