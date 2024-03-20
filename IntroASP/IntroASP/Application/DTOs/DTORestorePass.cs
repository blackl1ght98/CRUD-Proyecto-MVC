﻿using System.ComponentModel.DataAnnotations;

namespace IntroASP.Application.DTOs
{
    public class DTORestorePass
    {
        public int UserId { get; set; }
        public string Token { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string TemporaryPassword { get; set; }
    }
}
