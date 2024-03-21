using IntroASP.Application.DTOs;

namespace IntroASP.Interfaces.Application
{
    public interface IConfirmEmailService
    {
        Task ConfirmEmail(DTOConfirmRegistration confirm);

    }
}
