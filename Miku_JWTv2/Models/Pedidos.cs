namespace Miku_JWTv2.Models
{
    public class Pedidos
    {
        public string? ciudad_envio { get; set; } // Propiedad que almacena la ciudad de envío del pedido
        public string? fecha_pedido { get; set; } // Propiedad que almacena la fecha de pedido en formato de cadena
        public string? nombre_pago { get; set; } // Propiedad que almacena el nombre del método de pago utilizado
        public decimal? pago_total { get; set; } // Propiedad que almacena el monto total del pago del pedido
        public string? nombre_estado { get; set; } // Propiedad que almacena el nombre del estado del pedido
    }
}
