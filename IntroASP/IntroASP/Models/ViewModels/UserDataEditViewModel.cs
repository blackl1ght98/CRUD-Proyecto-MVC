namespace IntroASP.Models.ViewModels
{
    public class UserDataEditViewModel
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string NombreCompleto { get; set; }
        public DateTime? FechaNacimiento { get; set; }
        public string Telefono { get; set; }
        public string Direccion { get; set; }
    }
}
