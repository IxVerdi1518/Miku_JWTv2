using Microsoft.Data.SqlClient;

namespace Miku_JWTv2.DAO
{
    public class DbConnection
    {
        private readonly IConfiguration _configuration;

        public DbConnection(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Método protegido para obtener una conexión SqlConnection
        protected SqlConnection GetSqlConnection()
        {
            // Obtener la cadena de conexión del archivo de configuración
            string connectionString = _configuration.GetConnectionString("conexion");
            if (!string.IsNullOrEmpty(connectionString)) // Verificar si la cadena de conexión no está vacía
            {
                return new SqlConnection(connectionString); // Crear y retornar una nueva instancia de SqlConnection con la cadena de conexión
            }
            else
            {
                // Si la cadena de conexión es nula o vacía, lanzar una excepción
                throw new ApplicationException("La cadena de conexión es nula o vacía.");
            }
        }
    }
}
