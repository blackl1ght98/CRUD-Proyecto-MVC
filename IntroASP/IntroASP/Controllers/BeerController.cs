using Azure;
using IntroASP.Models;
using IntroASP.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace IntroASP.Controllers
{
    public class BeerController : Controller
    {
        private readonly PubContext _context;

        public BeerController(PubContext context)
        {
            _context = context;
        }
        //Obtiene datos
        public  async Task<IActionResult> Index()
        {
            var beers= await _context.Beers.Include(x=>x.Brand).ToListAsync();
            return View(beers);
        }
        //Porque dos metodos create facil uno trae los datos y el otro los crea
        public IActionResult Create()
        {
           
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
             * new SelectList()--> recibe 4 parametros:
             *    _context.Brands: uno es la funente de informacion.
             *   "BrandId": como segundo parametro se pone la informacion que queramos obtener en este caso la informacion que tenga el id en este caso es BrandId.
             *    "Name": como tercer parametro es la informacion que va a ver el usuario que es el Nombre(Name) que esta relacionada con el BrandId.
             *    model.BrandId: como cuarto parametro tenemos que decir cual hemos seleccionado  que esto se consigue poniendo el modelo y lo que selecciones(el Nombre)
             *    deberia estar vinculado a brandId
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
            if (id == null)
            {
                return NotFound();
            }

            var beer = await _context.Beers
    
    .FirstOrDefaultAsync(m => m.BeerId == id);

            if (beer == null)
            {
                return NotFound();
            }

            return View(beer);
        }

       
        [HttpPost, ActionName("DeleteConfirmed")]
        [ValidateAntiForgeryToken]
        //Para que detecte la id de la cerveza es necesario poner el mismo nombre que se ponga en la vista en la
        //parte del asp-for del formulario
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
     
        //Aqui no haria falta cambiarlo a BeerId, porque esto solo se encarga de obtener el id
        //que corresponde a la cerveza a editar
        public async Task<ActionResult> Edit(int id)
        {
            Beer beer = await _context.Beers.FindAsync(id);
            return View(beer);
        }

       

        [HttpPost]
        public async Task<ActionResult> Edit(Beer beer)
        {
            //Esta línea verifica si el modelo Beer es válido. Esto significa que todos los campos
            //requeridos están presentes y que todos los datos cumplen con las reglas de validación.
            if (ModelState.IsValid)
            {
                try

                {
                   // Estas líneas intentan actualizar el objeto Beer en la base de datos.
                   // _context.Entry(beer).State = EntityState.Modified; marca el objeto Beer como modificado,
                   // lo que significa que se deben guardar los cambios en la base de datos.
                   // await _context.SaveChangesAsync(); guarda los cambios en la base de datos.
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
