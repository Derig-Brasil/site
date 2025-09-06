$(document).ready(function() {
	$("#cep").blur(function() {
		//Consulta o webservice viacep.com.br/
		var cep = $("#cep").val();
		$.getJSON("https://viacep.com.br/ws/"+ cep +"/json/?callback=?", function(dados) {

		    if (!("erro" in dados)) {
		        //Atualiza os campos com os valores da consulta.
		        $("#rua").val(dados.logradouro);
		        $("#bairro").val(dados.bairro);
		        $("#cidade").val(dados.localidade);
		        $("#uf").val(dados.uf);
		    } //end if.
		    else {
		        alert("CEP inválido!");
		    }
		});
	});
});