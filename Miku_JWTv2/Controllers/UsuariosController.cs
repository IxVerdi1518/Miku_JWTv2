using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Miku_JWTv2.DAO;
using Miku_JWTv2.Models;
using Newtonsoft.Json;
using System.Security.Claims;

namespace Miku_JWTv2.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UsuariosDAO _usuariosDAO;
        public IConfiguration _configuration;
        public UsuariosController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        //public UsuariosController(UsuariosDAO usuariosDAO)
        //{
        //    _usuariosDAO = usuariosDAO;
        //}
        //public dynamic IniciarSesion([FromBody] Object optData)
        //{
        //    var data = JsonConvert.DeserializeObject<dynamic>(optData.ToString());

        //    string user = data.usuario.ToString();
        //    string contra = data.contraseña.ToString();

            
        //}
        [HttpPost]
        public async Task<IActionResult> Login(Usuarios user)
        {
            //try
            //{
                // Se valida el usuario en la base de datos y se obtiene su información
                ((int id_usuario, int id_rol_user), int id_cliente) = _usuariosDAO.ValidarUsuario(user);
            if (id_usuario != 0)
            {
                var claims = new List<Claim> // Se crean las reclamaciones para el usuario autenticado
                    {
                    new Claim(ClaimTypes.Name, user.correo_elec),
                    new Claim("id_usuario", id_usuario.ToString()),
                    new Claim("id_cliente", id_cliente.ToString()),
                    new Claim("id_rol_user", id_rol_user.ToString())

                    };
                // Agregar una reclamación específica para el rol del usuario
                if (id_rol_user == 1)
                {
                    claims.Add(new Claim("id_rol_user", "1")); // Administrador
                }
                else
                {
                    claims.Add(new Claim("id_rol_user", "2")); // Usuario normal
                }
                // Se crea la identidad del usuario y se realiza la autenticación
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                if (id_rol_user == 1)
                {
                    return RedirectToAction("Administrador", "Administrador"); // Redirige al panel de administración si es un administrador
                }
                else
                {
                    // Se registra una auditoría y se redirige a la página principal
                    _usuariosDAO.RegistrarAuditoria(id_usuario, DateTime.Now, true);
                    return RedirectToAction("Index", "Home");
                }
            }
            else
            {
                return new
                {
                    success = false,
                    message = "Creedenciales Incorrectas",
                    result = ""
                };
            }
            var jwt = _configuration.GetSection("Jwt");
            //}
            //catch (System.Exception)
            //{
            //    ViewBag.Error = "Credenciales incorrectas"; // Muestra un mensaje de error si las credenciales son incorrectas
            //    return View();
            //}
        }
    }
}
