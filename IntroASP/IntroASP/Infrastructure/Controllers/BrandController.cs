using IntroASP.Models;
using IntroASP.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace IntroASP.Infrastructure.Controllers
{
    [Authorize(Roles ="usuario")]
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
        //Reedirige a la vista de creacion
        public IActionResult Create()
        {


            return View();
        }

        [HttpPost]

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(BrandViewModel model)
        {
            //Esto toma en cuenta las validaciones puestas en BeerViewModel
            if (ModelState.IsValid)
            {
                var beer = new Brand()
                {
                    Name = model.Name,
                    BrandId = model.BrandId,
                };
                _context.Add(beer);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Los datos se han creado con éxito.";

                return RedirectToAction(nameof(Index));
            }
            return View(model);

        }
        //Obtiene los datos a eliminar
        public async Task<IActionResult> Delete(int id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var brand = await _context.Brands

    .FirstOrDefaultAsync(m => m.BrandId == id);

            if (brand == null)
            {
                return NotFound();
            }

            return View(brand);
        }

        //Realiza la accion de eliminar
        [HttpPost, ActionName("DeleteConfirmed")]
        [ValidateAntiForgeryToken]
        //Para que detecte la id de la cerveza es necesario poner el mismo nombre que se ponga en la vista en la
        //parte del asp-for del formulario
        public async Task<IActionResult> DeleteConfirmed(int BrandId)
        {
            var brand = await _context.Brands.Include(x => x.Beers).FirstOrDefaultAsync(m => m.BrandId == BrandId);
            if (brand == null)
            {
                return BadRequest();
            }
            _context.Beers.RemoveRange(brand.Beers);
            _context.Brands.Remove(brand);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Los datos se han eliminado con éxito.";

            return RedirectToAction(nameof(Index));
        }
        //Obtencion de los datos a editar, va a la vista para editar
        public async Task<ActionResult> Edit(int id)
        {
            Brand brand = await _context.Brands.FindAsync(id);
            return View(brand);
        }


        [HttpPost]
        public async Task<ActionResult> Edit(Brand brand)
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
                    _context.Entry(brand).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Los datos se han modificado con éxito.";

                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!BeerExists(brand.BrandId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        _context.Entry(brand).Reload();

                        // Intenta guardar de nuevo
                        _context.Entry(brand).State = EntityState.Modified;
                        await _context.SaveChangesAsync();
                    }
                }
                return RedirectToAction("Index");
            }
            return View(brand);
        }

        private bool BeerExists(int BrandId)
        {
            Console.WriteLine("BeerId: " + BrandId);  // Agrega esta línea para depurar
            return _context.Brands.Any(e => e.BrandId == BrandId);
        }
    }
}
