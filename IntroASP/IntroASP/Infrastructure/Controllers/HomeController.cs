﻿using IntroASP.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace IntroASP.Infrastructure.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
        public IActionResult AccessDenied()
        {
            return View();
        }


    }
}
