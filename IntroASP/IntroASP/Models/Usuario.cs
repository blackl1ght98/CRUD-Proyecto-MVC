﻿using System;
using System.Collections.Generic;

namespace IntroASP.Models;

public partial class Usuario
{
    public int Id { get; set; }

    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public byte[] Salt { get; set; } = null!;

    public int IdRol { get; set; }

    public bool ConfirmacionEmail { get; set; }

    public bool BajaUsuario { get; set; }

    public string? EnlaceCambioPass { get; set; }

    public DateTime? FechaEnlaceCambioPass { get; set; }

    public string NombreCompleto { get; set; } = null!;

    public DateTime? FechaNacimiento { get; set; }

    public string? Telefono { get; set; }

    public string Direccion { get; set; } = null!;

    public DateTime? FechaRegistro { get; set; }

    public string? TemporaryPassword { get; set; }

    public virtual Role IdRolNavigation { get; set; } = null!;
}
