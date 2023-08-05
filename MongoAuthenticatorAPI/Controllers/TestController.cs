using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace MongoAuthenticatorAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TestController : ControllerBase
    {
        [HttpPost()]
        public IActionResult Test()
        {
            return null;
        }
    }
}
