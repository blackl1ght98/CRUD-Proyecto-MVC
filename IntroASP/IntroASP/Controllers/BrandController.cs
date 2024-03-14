using IntroASP.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IntroASP.Controllers
{
    public class BrandController : Controller
    {
        //Al igual que en un proyecto tipo web api se crea un controlador vacio aqui se crea igual
        //Los controller que son tipo mvc se diferencian en el que el controller tipo mvc hereda de Controller
        //mientras que los controllers empleados en un proyecto web api heredan de ControllerBase.
        //Los controller que heredan de Controller permiten la integracion de vistas esto quiere decir 
        //que al hacer una consulta ha base de datos tu puedes contruir un archivo cshtml en el que se muestren los datos
        //de la consulta como por ejemplo aqui:
        /*public async Task<IActionResult> Index()
        {
            return View(await _context.Brands.ToListAsync());
        } aqui los datos van a una vista esta vista esta en una carpeta de nombre Brand que corresponde al mismo nombre que tiene
        nuestro controlador y el nombre de la vista corresponde al nombre del metodo*/
        //La vista que crea es un archivo cshtml, pero basicamente contiene codigo html pero no solo html  puede combinarse con c#
        //lo cual vuelve el html un html dinamico
        //Aqui todo acceso a base de datos que se ponga por defecto es de tipo GET(obtencion de datos) a no ser que se ponga que sea
        //POST, PUT o DELETE
        private readonly PubContext _context;

        public BrandController(PubContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _context.Brands.ToListAsync());
        }
        //Manera avanzada
        //public async Task<IActionResult> Index2()
        
        // => View(await _context.Brands.ToListAsync());
        
    }
}
