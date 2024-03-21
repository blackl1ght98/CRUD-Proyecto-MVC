using IntroASP.Application.DTOs;
using IntroASP.Models;

namespace IntroASP.Interfaces.Application
{
    public interface IChangePassService
    {
        Task ChangePassId(Usuario usuarioDB, string newPass);

    }
}
