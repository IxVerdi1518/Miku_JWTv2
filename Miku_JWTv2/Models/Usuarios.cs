using System.ComponentModel.DataAnnotations;

namespace Miku_JWTv2.Models
{
    public class Usuarios
    {
        [Key] // Atributo que indica que esta propiedad es la clave primaria de la entidad
        public int id_usuario { get; set; }

        [EmailAddress] // Valida que el valor de la propiedad sea una dirección de correo electrónico válida
        [StringLength(50)] // Limita la longitud máxima de la cadena a 50 caracteres
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string? correo_elec { get; set; }

        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string? contrasena { get; set; } // Indica que representa al campo de la contraseña

        public int id_rol_user { get; set; } // Propiedad que representa el identificador del rol del usuario
    }
}
