using IntroASP.Application.DTOs;

namespace IntroASP.Application.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAsyncRegister(DTOEmail userData);
        Task SendEmailAsyncChangePassword(DTOEmail userData);
        Task SendTempPassword(DTOEmail userData);
    }
}
