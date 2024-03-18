using Azure;
using IntroASP.Models;
using IntroASP.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace IntroASP.Infrastructure.Controllers
{
    [Authorize]
    public class BeerController : Controller
    {
        //Inyeccion de dependencias
        private readonly PubContext _context;

        public BeerController(PubContext context)
        {
            _context = context;
        }
        //Obtiene datos, para tener como una plantilla donde poner las operaciones a realizar esto
        //lo tiene cualquier vista mvc lo cual hace que tu pagina sea mucho mas interactiva al usuario
        //y mejora la comprension de la misma
        public async Task<IActionResult> Index()
        {
            var beers = await _context.Beers.Include(x => x.Brand).ToListAsync();
            return View(beers);
        }
        //¿Porque dos metodos Create? facil uno trae los datos y el otro los crea
        public IActionResult Create()
        {
            //obtiene los datos para el desplegable que se va a crear
            ViewData["Brands"] = new SelectList(_context.Brands, "BrandId", "Name");
            return View();
        }
        //Si no se le pone nada es tipo get aqui como se ha especificado que sea post pues va
        //a ser una post 
        [HttpPost]
        //Lo que hace que la informacion la va a esperar del formulario que esta en el mismo dominio
        //de tu sitio con esto evitamos que nos manden informacion de fuera 
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(BeerViewModel model)
        {
            //Esto toma en cuenta las validaciones puestas en BeerViewModel
            if (ModelState.IsValid)
            {
                var beer = new Beer()
                {
                    Name = model.Name,
                    BrandId = model.BrandId,
                };
                _context.Add(beer);
                await _context.SaveChangesAsync();
                //retornamos aqui para ver las cervezas agregadas 
                return RedirectToAction(nameof(Index));
            }



            //Cuando agregamos una cerveza necesitamos el nombre y la marca vamos a ir a  la base de datos
            //pero no de manera asincrona. ¿Como se guarda la informacion sin usar el async? pues vamos a 
            //guardarlo en algo llamado ViewData que es un diccionario que cuando ejecutas el controlador este
            //diccionario tambien llega no como modelo pero llega como un diccionario al cual puedes acceder 
            //desde la vista para acceder a este diccionario basta con poner:
            /*ViewData["Brands"]--> El nombre entre corchetes puede ser el que queramos nosotros.
             * new SelectList()-->Crea una lista desplegable que recibe 4 parametros
             * 
             *    _context.Brands: uno es la funente de informacion.
             *   "BrandId": como segundo parametro se obtiene la id de cada marca que lo que tiene asociado esa id es un nombre
             *    "Name": como tercer parametro es la informacion que va a ver el usuario que es el Nombre(Name) que esta relacionada con el BrandId.
             *    model.BrandId:  Este es el valor seleccionado en la lista desplegable. En este caso se  está utilizando el ID de la marca seleccionada en el modelo.
             * 
             * La informacion que va al formulario es BrandId pero la que se muestra es el Name
             * Para  obtener la fuente de informacion ponemos esto _context.Brands como primer parametro
             */

            ViewData["Brands"] = new SelectList(_context.Brands, "BrandId", "Name", model.BrandId);
            return View(model);

        }
        // GET: Beer/Delete/5
        public async Task<IActionResult> Delete(int id)
        {
            //Si el id es nulo da un error 404
            if (id == null)
            {
                return NotFound("Cerveza no encontrada");
            }
            //Consulta a base de datos
            var beer = await _context.Beers

    .FirstOrDefaultAsync(m => m.BeerId == id);
            //Si no hay cervezas muestra el error 404
            if (beer == null)
            {
                return NotFound("Cervezas no encontradas");
            }
            //Llegados ha este punto hay cervezas por lo tanto se muestran las cervezas
            return View(beer);
        }


        [HttpPost, ActionName("DeleteConfirmed")]
        [ValidateAntiForgeryToken]
        //Para que detecte la id de la cerveza es necesario poner el mismo nombre que se ponga en la vista en la
        //parte del asp-for del formulario tenemos BeerId por lo tanto aqui tambien hay que ponerlo
        public async Task<IActionResult> DeleteConfirmed(int BeerId)
        {
            var beer = await _context.Beers.FirstOrDefaultAsync(m => m.BeerId == BeerId);
            if (beer == null)
            {
                return BadRequest();
            }
            _context.Beers.Remove(beer);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

      //Se obtiene la cerveza a editar
        public async Task<ActionResult> Edit(int id)
        {
            Beer beer = await _context.Beers.FindAsync(id);
            ViewData["Brands"] = new SelectList(_context.Brands, "BrandId", "Name", id);

            return View(beer);
        }


        //El motivo por el cual se usa HttpPost y no HttpPut es porque en un proyecto mvc como backend y front son uno
        //los formularios solo admiten get o post, si se quiere realizar una edicion se necesita un formulario
        //y como he dicho antes los formularios solo admiten get o post aunque tu lo pongas con post si la logica interna la 
        //la configuras para que se pueda editar hara una edicion y no un post
        [HttpPost]
        public async Task<ActionResult> Edit(Beer beer)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    // Carga la Brand desde la base de datos
                    beer.Brand = await _context.Brands.FindAsync(beer.BrandId);
                    ViewData["Brands"] = new SelectList(_context.Brands, "BrandId", "Name", beer.BrandId);

                    _context.Entry(beer).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!BeerExists(beer.BeerId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction("Index");
            }
            return View(beer);
        }

        private bool BeerExists(int BeerId)
        {
            Console.WriteLine("BeerId: " + BeerId);  // Agrega esta línea para depurar
            return _context.Beers.Any(e => e.BeerId == BeerId);
        }






    }
}
