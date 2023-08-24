using System.ComponentModel.DataAnnotations;

namespace Miku_JWTv2.Models
{
    public class Clientes
    {
        [Key] // Atributo que indica que esta propiedad es la clave primaria de la entidad
        public int? id_cliente { get; set; }

        [EmailAddress] // Valida que el valor de la propiedad sea una dirección de correo electrónico válida
        [StringLength(25)] // Limita la longitud máxima de la cadena a 25 caracteres
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string correo_nuevo { get; set; }

        [MaxLength(20, ErrorMessage = "Máximo 20 caracteres")] // Establece la longitud máxima permitida para la cadena y el mensaje de error personalizado si se excede
        [MinLength(3, ErrorMessage = "Mínimo 3 caracteres")] // Establece la longitud mínima permitida para la cadena y el mensaje de error personalizado si no se cumple
        [StringLength(15)] // Limita la longitud máxima de la cadena a 15 caracteres
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string nombre_cliente { get; set; }

        [MinLength(3, ErrorMessage = "Mínimo 3 caracteres")] // Establece la longitud mínima permitida para la cadena y el mensaje de error personalizado si no se cumple
        [StringLength(15)] // Limita la longitud máxima de la cadena a 15 caracteres
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string apellido_cliente { get; set; }

        [StringLength(10)] // Limita la longitud máxima de la cadena a 10 caracteres
        [MinLength(10, ErrorMessage = "Se requieren 10 caracteres")] // Establece la longitud mínima permitida para la cadena y el mensaje de error personalizado si no se cumple
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string telefono_cliente { get; set; }

        [MinLength(6, ErrorMessage = "La contraseña debe tener al menos 6 caracteres.")] // Establece la longitud mínima permitida para la cadena y el mensaje de error personalizado si no se cumple
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string contrasena_nueva { get; set; }

        [MinLength(6, ErrorMessage = "La contraseña debe tener al menos 6 caracteres.")] // Establece la longitud mínima permitida para la cadena y el mensaje de error personalizado si no se cumple
        [Required(ErrorMessage = "Campo requerido")] // Indica que esta propiedad es requerida y establece el mensaje de error personalizado
        public string? confirmar_contrasena { get; set; } // El signo de interrogación indica que esta propiedad puede ser nula
    }
}
