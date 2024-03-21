using IntroASP.Application.DTOs;
using IntroASP.Application.Services;
using IntroASP.Interfaces.Application;
using IntroASP.Models;
using IntroASP.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace IntroASP.Infrastructure.Controllers
{
    [Authorize(Roles ="usuario, administrador")]
    public class UserDataController : Controller
    {
        private readonly PubContext _context;
        private readonly HashService _hashService;
        private readonly IEmailService _emailService;

        public UserDataController(PubContext context, HashService hashService, IEmailService emailService)
        {
            _context = context;
            _hashService = hashService;
            _emailService = emailService;
        }

        public async Task<IActionResult> Index()
        {
            var existeUsuario = User.FindFirstValue(ClaimTypes.NameIdentifier);
            int usuarioId;
            UserDataEditViewModel viewModel = null;

            if (int.TryParse(existeUsuario, out usuarioId))
            {
                var usuario = await _context.Usuarios.FindAsync(usuarioId);
                // Creas un nuevo ViewModel y llenas sus propiedades con los datos del usuario
                viewModel = new UserDataEditViewModel
                {
                    Id = usuarioId,
                    Email = usuario.Email,
                    Password = usuario.Password,
                    NombreCompleto = usuario.NombreCompleto,
                    FechaNacimiento = usuario.FechaNacimiento,
                    Telefono = usuario.Telefono,
                    Direccion = usuario.Direccion
                };
            }

            if (viewModel == null)
            {
                // Aquí puedes manejar el caso cuando no hay un usuario logueado
                // Por ejemplo, puedes redirigir al usuario a la página de inicio de sesión
                return RedirectToAction("Index");
            }

            return View(viewModel);
        }
        [HttpPost]
        public async Task<ActionResult> Edit(UserDataEditViewModel userVM)
        {
            if (ModelState.IsValid)
            {
                // Obtén la entidad Usuario correspondiente de la base de datos
                var user = await _context.Usuarios.FindAsync(userVM.Id);

                if (user == null)
                {
                    return NotFound();
                }


                var resultadoHash = _hashService.Hash(userVM.Password);

                // Mapea los datos del ViewModel a la entidad

                user.Password = resultadoHash.Hash;
                user.Salt = resultadoHash.Salt;
                user.NombreCompleto = userVM.NombreCompleto;
                user.FechaNacimiento = userVM.FechaNacimiento;
                user.Telefono = userVM.Telefono;
                user.Direccion = userVM.Direccion;



                if (user != null && user.Email != userVM.Email)
                {

                    user.ConfirmacionEmail = false;
                    user.Email = userVM.Email;
                    _context.Usuarios.Update(user);
                    await _context.SaveChangesAsync();
                    await _emailService.SendEmailAsyncRegister(new DTOEmail
                    {
                        ToEmail = userVM.Email
                    });
                }
                else
                {
                    user.Email = userVM.Email;
                }



                try
                {
                    _context.Entry(user).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Los datos se han modificado con éxito.";

                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!UserExists(user.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        _context.Entry(user).Reload();

                        // Intenta guardar de nuevo
                        _context.Entry(user).State = EntityState.Modified;
                        await _context.SaveChangesAsync();
                    }
                }
                return RedirectToAction("Index");
            }
            return View(userVM);
        }
        private bool UserExists(int Id)
        {

            return _context.Usuarios.Any(e => e.Id == Id);
        }
    }
}
