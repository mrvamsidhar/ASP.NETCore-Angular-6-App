using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController:ControllerBase
    {
        private readonly IAuthRepository _repository;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repository,IConfiguration config)
        {
            this._repository = repository;
            this._config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
            if(await _repository.UserExists(userForRegisterDto.Username))
                return BadRequest("Username already exists");
            var userToCreate = new User
            {
                Username = userForRegisterDto.Username
            };
            var createdUser = await _repository.Register(userToCreate,userForRegisterDto.Password);
            return StatusCode(201);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForRegisterDto)
        {
            throw new Exception("computer says no.");
            var userFromRepo = await _repository.Login(userForRegisterDto.Username.ToLower(),userForRegisterDto.Password);
            if(userFromRepo == null)
                return Unauthorized();
            var claims = new[] 
            {
                new Claim(ClaimTypes.NameIdentifier,userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);
            var tokendescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };
            var tokenhandler = new JwtSecurityTokenHandler();
            var token = tokenhandler.CreateToken(tokendescriptor);
            return Ok(new {
                token = tokenhandler.WriteToken(token)
            });
        }
    }
}