﻿using System.ComponentModel.DataAnnotations;

namespace IntroASP.Models.ViewModels
{
    public class UserViewModel
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
   
        public int IdRol {  get; set; }
        [Required]
        public string NombreCompleto { get; set; }
        [Required]
        public DateTime? FechaNacimiento { get; set; }
        public string Telefono { get; set; }
        public string Direccion { get; set; }
    }
}
