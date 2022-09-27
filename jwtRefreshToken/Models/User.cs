namespace jwtRefreshToken.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] Password { get; set; }
        public byte[] PassworSalt { get; set; }
        public RefreshToken RefreshT { get; set; }
      

    }
}
