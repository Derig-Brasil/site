$(function(){

  $.validator.setDefaults({
     errorClass: 'help-block',
     highlight: function(element) {
       $(element)
         .closest('.form-group')
         .addClass('has-error');
     },
     unhighlight: function(element) {
       $(element)
         .closest('.form-group')
         .removeClass('has-error');
     },
   });

 $.validator.addMethod('numbersonly', function(value, element) {
   return this.optional(element)//se for opcional ignora o resto
   || /^[0-9]+$/i.test(value);//verifica se contém pelo menos um caractere
 }, "Apenas números!");

 var validator = $("#cadastroForm").validate({
   rules: {
     //Informações Pessoais
     nome: {
       required: true
     },
     email: {
       required: true,
       email: true
     },
     cpf: {
       required: true,
       minlength: 14
     },
     rg: {
       required: true
     },
     dataNascimento: {
       required: true,
       minlength: 10
     },
     foneFixo: {
       required: true,
       minlength: 14
     },
     celular: {
       required: true,
       minlength: 14
     },
     //Informações Profissionais
     cro: {
       required: true,
       numbersonly: true
     },
     croUf: {
       required: true
     },
     especialidade: {
       required: true
     },
     //Endereço
     cep: {
       required: true,
       minlength: 9
     },
     rua: {
       required: true
     },
     numero: {
       required: true
     },
     bairro: {
       required: true
     },
     cidade: {
       required: true
     },
     uf: {
       required: true
     }
   },
   messages: {
     //Informações Pessoais
     nome: {
       required: "Informe o seu nome!"
     },
     email: {
       required: "Informe um e-mail válido!"
     },
     cpf: {
       required: "Informe seu CPF!",
       minlength: "Informe um CPF válido!"
     },
     rg: {
       required: "Informe seu RG!",
       minlength: "Informe um RG válido!"
     },
     dataNascimento: {
       required: "Informe sua data de nascimento!",
       minlength: "Informe uma data válida!"
     },
     foneFixo: {
       required: "Informe um número de telefone!",
       minlength: "Informe um telefone válido!"
     },
     celular: {
       required: "Informe um número de celular!",
       minlength: "Informe um celular válido!"
     },
     //Informações Profissionais
     cro: {
       required: "Informe o CRO!"
     },
     croUf: {
       required: "Informe o UF"
     },
     especialidade: {
       required: "Selecione uma especialidade!"
     },
     //Endereço
     cep: {
       required: "Informe seu CEP!",
       minlength: "Informe um CEP válido!"
     },
     rua: {
       required: "Informe o nome de sua rua!"
     },
     numero: {
       required: "Informe o número de sua residência!"
     },
     bairro: {
       required: "Informe o nome do bairro!"
     },
     cidade: {
       required: "Informe o nome da cidade!"
     },
     uf: {
       required: "Informe o estado!"
     }
   }
 });

 var options = {
   onKeyPress: function (cpf, ev, el, op) {
       var masks = ['000.000.000-000', '00.000.000/0000-00'],
           mask = (cpf.length > 14) ? masks[1] : masks[0];
       el.mask(mask, op);
   }
 }

});