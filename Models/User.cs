namespace Auth.Models
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; }

        public byte[]  PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
