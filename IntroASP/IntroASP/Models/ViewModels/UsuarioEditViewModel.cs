﻿using System.ComponentModel.DataAnnotations;

namespace IntroASP.Models.ViewModels
{
    public class UsuarioEditViewModel
    {
        public int Id { get; set; }

        [Required]
        public string Email { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
        [Required]
        public string NombreCompleto { get; set; } = null!;

        [Required]
        public DateTime? FechaNacimiento { get; set; }

        [Required]
        public string? Telefono { get; set; }

        [Required]
        public string Direccion { get; set; } = null!;
    }
}
