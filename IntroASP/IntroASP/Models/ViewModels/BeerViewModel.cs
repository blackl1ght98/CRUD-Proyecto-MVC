using System.ComponentModel.DataAnnotations;

namespace IntroASP.Models.ViewModels
{
    public class BeerViewModel
    {
        //Esto es una clase para formularios, esto es para que el formulario siga una estructura
        [Required]
        [Display(Name = "Nombre")]
        public string Name { get; set; }
        [Required]
        [Display(Name = "Marca")]
        public int BrandId { get; set; }
    }
}
