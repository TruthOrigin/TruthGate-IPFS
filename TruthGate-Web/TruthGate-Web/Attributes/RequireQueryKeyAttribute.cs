using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;

namespace TruthGate_Web.Attributes
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    sealed class RequireQueryKeyAttribute : ActionMethodSelectorAttribute, IActionConstraint
    {
        public int Order { get; set; } = 0;
        private readonly string _key;

        public RequireQueryKeyAttribute(string key) => _key = key;

        public bool Accept(ActionConstraintContext context)
            => context.RouteContext.HttpContext.Request.Query.ContainsKey(_key);

        public override bool IsValidForRequest(RouteContext routeContext, ActionDescriptor action)
            => routeContext.HttpContext.Request.Query.ContainsKey(_key);
    }
}
