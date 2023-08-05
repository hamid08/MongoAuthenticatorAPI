using System;
using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;

namespace MongoAuthenticatorAPI.Models
{
    [CollectionName("users")]
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        public string FirstName { get; set; } 
        public string LastName { get; set; }
        public string RefreshToken { get; set; }
        public DateTime ExpirationRefreshToken { get; set; }
        public DateTime CreateDateTime { get; set; } = DateTime.Now;
    }
}

