namespace jwtRefreshToken.Models
{
    public class RefreshToken
    {
        //id would have been provided if we used a database
        public string Token { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime ExpiresAt {get;set;}



    }
}
